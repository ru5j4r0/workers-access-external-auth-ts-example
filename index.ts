import type {
	ExecutionContext,
	JsonWebKeyWithKid,
} from '@cloudflare/workers-types/experimental';
import type { webcrypto } from 'node:crypto';
import type { PrivateKeyCipher } from 'pem';
import type { Env } from './worker-configuration';

/**
 * Where your business logic should go
 *
 * @param {*} claims - the claims from the JWT
 * @param {Request} request - the request object
 * @param {Env} env - the environment object
 * @returns {boolean} - true if the request is authorized, false otherwise
 */

// biome-ignore lint/suspicious/noExplicitAny: TODO: claims should be typed
function externalAuth(claims: any, request: Request, env: Env): boolean {
	return !!claims && !!request && !!env;
}

// Utils added by me
// ==================
type CryptoKey = webcrypto.CryptoKey;
type CryptoKeyPair = webcrypto.CryptoKeyPair;
type JsonWebKey = webcrypto.JsonWebKey;

interface Certs {
	keys: [JsonWebKeyWithKid, JsonWebKeyWithKid];
	publicCert: PrivateKeyCipher;
	publicCerts: [PrivateKeyCipher, PrivateKeyCipher];
}

// biome-ignore lint/suspicious/noExplicitAny: value is any
function isCerts(value: any): value is Certs {
	return (
		value.keys !== undefined &&
		value.public_cert !== undefined &&
		value.public_certs !== undefined
	);
}

async function fetchCerts(teamDomain: string): Promise<Certs> {
	const resp = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
	const keys: unknown = await resp.json();

	if (!isCerts(keys)) {
		throw new Error('failed to fetch keys');
	}

	return keys;
}

function getFirstKeyByKid(certs: Certs, kid: string): JsonWebKey {
	const key = certs.keys.filter((key: JsonWebKeyWithKid) => key.kid === kid)[0];

	if (key === undefined) {
		throw new Error('cannot find signing key');
	}

	return key;
}

interface Keyset {
	kid: string;
	private: JsonWebKey;
	public: JsonWebKey;
}

// biome-ignore lint/suspicious/noExplicitAny: value is any
function isKeyset(value: any): value is Keyset {
	return (
		value.kid !== undefined &&
		value.private !== undefined &&
		value.public !== undefined
	);
}

async function getKeyset(env: Env): Promise<Keyset | null> {
	const keyset = await env.KV.get(KV_SIGNING_KEY, 'json');
	if (isKeyset(keyset)) {
		return keyset;
	}

	return null;
}

interface SigningKey {
	kid: string;
	privateKey: CryptoKey;
}

interface GeneratedKeys {
	keypair: CryptoKeyPair;
	publicKey: JsonWebKey;
	privateKey: JsonWebKey;
	kid: string;
}

interface ExternalAuthResponse {
	token: string;
}

function isExternalAuthResponse(
	// biome-ignore lint/suspicious/noExplicitAny: value is any
	value: any,
): value is ExternalAuthResponse {
	return value.token !== undefined;
}

async function fetchToken(request: Request): Promise<string> {
	const json = await request.json();

	if (!isExternalAuthResponse(json)) {
		throw new Error('invalid response body');
	}

	return json.token;
}

interface ExternalAuthResult {
	success: boolean;
	nonce?: string;
	iat: number;
	exp: number;
}

function isTriple(value: string[]): value is [string, string, string] {
	return value.length === 3;
}

// EVERYTHING PAST THIS SHOULD NOT NEED TO CHANGE UNLESS YOU WANT TO
// ==================================================================

// biome-ignore lint/style/noDefaultExport: Cloudflare needs it
export default {
	fetch(request: Request, env: Env, _: ExecutionContext): Promise<Response> {
		if (request.url.endsWith('keys')) {
			return handleKeysRequest(env);
		}

		return handleExternalAuthRequest(request, env);
	},
};

// the key in KV that holds the generated signing keys
const KV_SIGNING_KEY = 'external_auth_keys';

/*
 * Helpers for converting to and from URL safe Base64 strings. Needed for JWT encoding.
 */
const base64url = {
	stringify: (a: number[]) => {
		const base64string = btoa(String.fromCharCode.apply(0, a));
		return base64string
			.replace(/=/g, '')
			.replace(/\+/g, '-')
			.replace(/\//g, '_');
	},
	parse: (s: string) => {
		const decoded = s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
		return new Uint8Array(
			Uint8Array.from(atob(decoded), (c: string): number => c.charCodeAt(0)),
		);
	},
};

/**
 * Generate a key id for the key set
 *
 * @param {string} publicKey - the public key in JWK format
 * @returns {Promise<string>} - the key id
 */
async function generateKid(publicKey: string): Promise<string> {
	const msgUint8 = new TextEncoder().encode(publicKey);
	const hashBuffer = await crypto.subtle.digest('SHA-1', msgUint8);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	const hashHex = hashArray
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
	return hashHex.substring(0, 64);
}

/*
 * Helper to get from an ascii string to a literal byte array.
 * Necessary to get ascii string prepped for base 64 encoding
 */
function asciiToUint8Array(str: string) {
	const chars = [];
	for (let i = 0; i < str.length; ++i) {
		chars.push(str.charCodeAt(i));
	}
	return new Uint8Array(chars);
}

/**
 * Helper to get the Access public keys from the certs endpoint
 *
 * @param {string} kid - The key id that signed the token
 * @param {Env} env - The environment object
 * @returns {Promise<CryptoKey>} - The public key
 */
async function fetchAccessPublicKey(kid: string, env: Env): Promise<CryptoKey> {
	const keys: Certs = await fetchCerts(env.TEAM_DOMAIN);
	const jwk = getFirstKeyByKid(keys, kid);
	const key = await crypto.subtle.importKey(
		'jwk',
		jwk,
		{
			name: 'RSASSA-PKCS1-v1_5',
			hash: 'SHA-256',
		},
		false,
		['verify'],
	);
	return key;
}

/**
 * Generate a key pair and stores them into Workers KV for future use
 *
 * @param {Env} env - The environment object
 * @returns {Promise<GeneratedKeys>} - The generated keys
 */
async function generateKeys(env: Env): Promise<GeneratedKeys> {
	try {
		const keypair = await crypto.subtle.generateKey(
			{
				name: 'RSASSA-PKCS1-v1_5',
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: 'SHA-256',
			},
			true,
			['sign', 'verify'],
		);
		const publicKey = await crypto.subtle.exportKey('jwk', keypair.publicKey);
		const privateKey = await crypto.subtle.exportKey('jwk', keypair.privateKey);
		const kid = await generateKid(JSON.stringify(publicKey));
		await env.KV.put(
			KV_SIGNING_KEY,
			JSON.stringify({ public: publicKey, private: privateKey, kid: kid }),
		);
		return { keypair, publicKey, privateKey, kid };
	} catch (_) {
		throw 'failed to generate keyset';
	}
}

/**
 * Load the signing key from KV
 *
 * @param {Env} env - The environment object
 * @returns {Promise<SigningKey>} - The signing key
 */
async function loadSigningKey(env: Env): Promise<SigningKey> {
	const keyset = await getKeyset(env);

	if (keyset === null) {
		throw new Error('cannot find signing key');
	}

	const signingKey = await crypto.subtle.importKey(
		'jwk',
		keyset.private,
		{
			name: 'RSASSA-PKCS1-v1_5',
			hash: 'SHA-256',
		},
		false,
		['sign'],
	);
	return { kid: keyset.kid, privateKey: signingKey };
}

/**
 * Get the public key in JWK format
 *
 * @param {Env} env - The environment object
 * @returns {Promise<JsonWebKeyWithKid>} - The public key
 */
async function loadPublicKey(env: Env): Promise<JsonWebKeyWithKid> {
	// if the JWK values are already in KV then just return that
	const keyset = await getKeyset(env);
	if (keyset !== null) {
		return { kty: 'RSA', kid: keyset.kid, ...keyset.public };
	}

	// otherwise generate keys and store the Keyset in KV
	const { kid, publicKey } = await generateKeys(env);
	return { kty: 'RSA', kid, ...publicKey };
}

/**
 * Turn a payload into a JWT
 *
 * @param {ExternalAuthResult} payload
 * @param {Env} env - The environment object
 * @returns {Promise<string>} - The JWT
 */
async function signJwt(payload: ExternalAuthResult, env: Env): Promise<string> {
	const { kid, privateKey } = await loadSigningKey(env);
	const header = {
		alg: 'RS256',
		kid: kid,
	};
	const encHeader = base64url.stringify(
		Array.from(asciiToUint8Array(JSON.stringify(header))),
	);
	const encPayload = base64url.stringify(
		Array.from(asciiToUint8Array(JSON.stringify(payload))),
	);
	const encoded = `${encHeader}.${encPayload}`;

	const sig = Array.from(
		new Uint8Array(
			await crypto.subtle.sign(
				'RSASSA-PKCS1-v1_5',
				privateKey,
				asciiToUint8Array(encoded),
			),
		),
	);
	return `${encoded}.${base64url.stringify(sig)}`;
}

/**
 * Parse a JWT into its respective pieces. Does not do any validation other than form checking.
 *
 * @param {string} token - jwt string
 * @returns the parsed JWT
 */
function parseJwt(token: string) {
	const tokenParts = token.split('.');

	if (!isTriple(tokenParts)) {
		throw new Error('token must have 3 parts');
	}

	const enc = new TextDecoder('utf-8');
	return {
		toBeValidated: `${tokenParts[0]}.${tokenParts[1]}`,
		header: JSON.parse(enc.decode(base64url.parse(tokenParts[0]))),
		payload: JSON.parse(enc.decode(base64url.parse(tokenParts[1]))),
		signature: tokenParts[2],
	};
}

/**
 * Validates the provided token using the Access public key set
 *
 * @param {string} token - the token to be validated
 * @param {Env} env - The environment object
 * @returns Returns the payload if valid, or throws an error if not
 */
async function verifyToken(token: string, env: Env) {
	const jwt = parseJwt(token);
	const key = await fetchAccessPublicKey(jwt.header.kid, env);

	const verified = await crypto.subtle.verify(
		'RSASSA-PKCS1-v1_5',
		key,
		base64url.parse(jwt.signature),
		asciiToUint8Array(jwt.toBeValidated),
	);

	if (!verified) {
		throw new Error('failed to verify token');
	}

	const claims = jwt.payload;
	const now = Math.floor(Date.now() / 1000);
	// Validate expiration
	if (claims.exp < now) {
		throw new Error('expired token');
	}

	return claims;
}

/**
 * Top level handler for public jwks endpoint
 *
 * @param {Env} env - The environment object
 * @returns {Promise<Response>} - The response object
 */
async function handleKeysRequest(env: Env): Promise<Response> {
	const keys = await loadPublicKey(env);
	return new Response(JSON.stringify({ keys: [keys] }), {
		status: 200,
		headers: { 'content-type': 'application/json' },
	});
}

/**
 * Top level handler for external evaluation requests
 *
 * @param {Request} request - The request object
 * @param {Env} env - The environment object
 * @returns {Promise<Response>} - The response object
 */
async function handleExternalAuthRequest(
	request: Request,
	env: Env,
): Promise<Response> {
	const now = Math.round(Date.now() / 1000);
	const result: ExternalAuthResult = {
		success: false,
		iat: now,
		exp: now + 60,
	};
	try {
		const token = await fetchToken(request);
		const claims = await verifyToken(token, env);

		if (claims) {
			result.nonce = claims.nonce;
			if (await externalAuth(claims, request, env)) {
				result.success = true;
			}
		}

		const jwt = await signJwt(result, env);
		return new Response(JSON.stringify({ token: jwt }), {
			headers: { 'content-type': 'application/json' },
		});

		// biome-ignore lint/suspicious/noExplicitAny: error should be any
	} catch (e: any) {
		return new Response(
			JSON.stringify({ success: false, error: e.toString(), stack: e.stack }),
			{
				status: 403,
				headers: { 'content-type': 'application/json' },
			},
		);
	}
}
