import { randomBytes, randomUUID, createHash, generateKeyPairSync, sign } from "node:crypto";

const sha256 = value => createHash("sha256").update(value).digest();
const u32 = value => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes; };
const bytesField = value => Buffer.concat([u32(value.length), value]);
export function signedClaim(token) {
  const identity = generateKeyPairSync("ed25519");
  const publicKey = identity.publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const session = generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const wireguard = generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const secret = Buffer.from(token, "base64url"); const size = Buffer.alloc(8); size.writeBigUInt64BE(BigInt(secret.length));
  const digest = sha256(Buffer.concat([Buffer.from("peerward/stored-secret/v1\0"), size, secret]));
  const id = randomUUID(); const nonce = randomBytes(32);
  const text = ["0.1.0", nonce, "Browser test device", "test", "linux", "test"];
  const transcript = Buffer.concat([Buffer.from("peerward/join-claim/v2\0"), u32(2), Buffer.from(id.replaceAll("-", ""), "hex"),
    digest, publicKey, session, wireguard, u32(5), ...text.map(value => bytesField(Buffer.from(value)))]);
  return { fingerprint: sha256(publicKey).toString("hex"), body: {
    schema_version: 2, claim_id: id, identity_public_key: publicKey.toString("base64url"), session_public_key: session.toString("base64url"),
    wireguard_public_key: wireguard.toString("base64url"), client_version: text[0], supported_wire_major: 5, nonce: nonce.toString("base64url"),
    device_name: text[2], device_model: text[3], platform: text[4], platform_version: text[5], signature: sign(null, transcript, identity.privateKey).toString("base64url"),
  }};
}
