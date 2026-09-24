import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { createServer } from "node:http";

const clientId = "peerward-console-e2e";
const clientSecret = "peerward-console-e2e-secret";

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function signingMaterial(keyId) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { keyId, privateKey, publicJwk: publicKey.export({ format: "jwk" }) };
}

function json(response, status, body) {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json",
  });
  response.end(JSON.stringify(body));
}

function redirect(response, destination) {
  response.writeHead(302, { "cache-control": "no-store", location: destination });
  response.end();
}

async function requestBody(request) {
  const parts = [];
  for await (const part of request) parts.push(part);
  return Buffer.concat(parts).toString("utf8");
}

export async function startOidcProvider(redirectUri, port = 29000) {
  let issuer;
  const callbackUrl = new URL(redirectUri);
  if (callbackUrl.protocol !== "http:"
    || callbackUrl.hostname !== "127.0.0.1"
    || callbackUrl.pathname !== "/auth/callback"
    || callbackUrl.search || callbackUrl.hash) {
    throw new Error("the E2E OIDC callback must be an exact loopback /auth/callback URL");
  }
  const codes = new Map();
  let role = "admin";
  const counters = { authorizations: 0, exchanges: 0, pkce_validations: 0, rotations: 0, reauthentications: 0 };
  let signing = signingMaterial("peerward-e2e-key-1");

  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", issuer);
    if (request.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
      json(response, 200, {
        issuer,
        authorization_endpoint: `${issuer}authorize`,
        token_endpoint: `${issuer}token`,
        jwks_uri: `${issuer}jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["EdDSA"],
        token_endpoint_auth_methods_supported: ["client_secret_basic"],
        scopes_supported: ["openid", "profile", "email"],
        claims_supported: ["iss", "sub", "aud", "exp", "iat", "nonce", "groups", "auth_time"],
        code_challenge_methods_supported: ["S256"],
      });
      return;
    }
    if (request.method === "GET" && url.pathname === "/jwks") {
      json(response, 200, {
        keys: [{
          ...signing.publicJwk,
          kid: signing.keyId,
          alg: "EdDSA",
          use: "sig",
        }],
      });
      return;
    }
    if (request.method === "GET" && url.pathname === "/authorize") {
      const state = url.searchParams.get("state");
      const nonce = url.searchParams.get("nonce");
      const challenge = url.searchParams.get("code_challenge");
      const valid = url.searchParams.get("client_id") === clientId
        && url.searchParams.get("redirect_uri") === redirectUri
        && url.searchParams.get("response_type") === "code"
        && url.searchParams.get("code_challenge_method") === "S256"
        && typeof state === "string" && state.length >= 16
        && typeof nonce === "string" && nonce.length >= 16
        && typeof challenge === "string" && challenge.length >= 32;
      if (!valid) {
        json(response, 400, { error: "invalid_authorization_request" });
        return;
      }
      const code = randomBytes(24).toString("base64url");
      codes.set(code, { challenge, nonce, role, authTime:Math.floor(Date.now()/1000) });
      if(url.searchParams.get("prompt")==="login" && url.searchParams.get("max_age")==="0") counters.reauthentications += 1;
      counters.authorizations += 1;
      signing = signingMaterial("peerward-e2e-key-2");
      counters.rotations += 1;
      const callback = new URL(redirectUri);
      callback.searchParams.set("code", code);
      callback.searchParams.set("state", state);
      redirect(response, callback.toString());
      return;
    }
    if (request.method === "POST" && url.pathname === "/token") {
      const expected = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
      const form = new URLSearchParams(await requestBody(request));
      const code = form.get("code");
      const flow = typeof code === "string" ? codes.get(code) : undefined;
      if (request.headers.authorization !== expected
        || form.get("grant_type") !== "authorization_code"
        || form.get("redirect_uri") !== redirectUri
        || !flow) {
        json(response, 401, { error: "invalid_grant" });
        return;
      }
      codes.delete(code);
      counters.exchanges += 1;
      const verifier = form.get("code_verifier") ?? "";
      const actualChallenge = createHash("sha256").update(verifier).digest("base64url");
      if (actualChallenge !== flow.challenge) {
        json(response, 400, { error: "invalid_grant" });
        return;
      }
      counters.pkce_validations += 1;
      const now = Math.floor(Date.now() / 1000);
      const encodedHeader = base64url(JSON.stringify({
        alg: "EdDSA",
        kid: signing.keyId,
        typ: "JWT",
      }));
      const encodedClaims = base64url(JSON.stringify({
        iss: issuer,
        sub: `peerward-console-e2e-${flow.role}`,
        aud: clientId,
        exp: now + 300,
        iat: now,
        auth_time: flow.authTime,
        nonce: flow.nonce,
        groups: [`peerward-${flow.role}`],
      }));
      const input = `${encodedHeader}.${encodedClaims}`;
      const signature = sign(null, Buffer.from(input), signing.privateKey).toString("base64url");
      json(response, 200, {
        access_token: "peerward-console-e2e-access-token",
        token_type: "Bearer",
        expires_in: 300,
        id_token: `${input}.${signature}`,
      });
      return;
    }
    // Loopback-only fixture control: subsequent real OIDC logins receive this role.
    if (request.method === "POST" && url.pathname === "/test-role") {
      const requested = (await requestBody(request)).trim();
      if (!["admin", "operator", "auditor", "viewer"].includes(requested)) {
        json(response, 400, { error: "invalid_role" });
      } else {
        role = requested;
        json(response, 200, { role });
      }
      return;
    }
    if (request.method === "GET" && url.pathname === "/debug") {
      json(response, 200, { ...counters, unused_codes: codes.size });
      return;
    }
    json(response, 404, { error: "not_found" });
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {issuer=`http://127.0.0.1:${server.address().port}/`;resolve();});
  });
  return {
    issuer,
    clientId,
    clientSecret,
    redirectUri,
    close: () => new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}
