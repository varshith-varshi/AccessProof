/** Optional source-ingestion attestation verification for certified RAG routes.
 *
 * IMPORTANT: only a separately trusted provider-ingestion worker may hold the
 * corresponding private signing key. The customer RAG app pins PUBLIC keys.
 * This does not prove source origin if signing happens on attacker-supplied data.
 */

export type AttestedResource = {
  sourceId: string;
  resourceId: string;
  chunkId?: string;
  content?: string;
  contentVersion?: string;
  contentAttestation?: string;
};

export class AttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttestationError";
  }
}

function decodeBase64Url(value: string): Uint8Array {
  if (!value || value.length > 8_000 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new AttestationError("INVALID_ATTESTATION_ENCODING");
  }
  const decoded = atob(value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(decoded, char => char.charCodeAt(0));
}

type SignedClaims = Record<string, unknown>;

export class SourceAttestationVerifier {
  private readonly keyPromises = new Map<string, Promise<CryptoKey>>();
  private readonly revokedKeyIds: ReadonlySet<string>;

  constructor(
    readonly tenantId: string,
    trustedRawPublicKeys: Record<string, Uint8Array>,
    readonly maxClockSkewSeconds = 30,
    revokedKeyIds: Iterable<string> = [],
  ) {
    if (!tenantId || !Object.keys(trustedRawPublicKeys).length ||
        !Number.isFinite(maxClockSkewSeconds) || maxClockSkewSeconds < 0 ||
        maxClockSkewSeconds > 300) {
      throw new AttestationError("ATTESTATION_TRUST_NOT_CONFIGURED");
    }
    this.revokedKeyIds = new Set(revokedKeyIds);
    for (const [keyId, rawKey] of Object.entries(trustedRawPublicKeys)) {
      if (!keyId || keyId.length > 128 || rawKey.length !== 32) {
        throw new AttestationError("INVALID_TRUSTED_INGESTION_KEY");
      }
      if (this.revokedKeyIds.has(keyId)) {
        throw new AttestationError("KEY_CANNOT_BE_TRUSTED_AND_REVOKED");
      }
      const isolatedKey = Uint8Array.from(rawKey);
      this.keyPromises.set(keyId, crypto.subtle.importKey(
        "raw", isolatedKey, { name: "Ed25519" }, false, ["verify"],
      ));
    }
  }

  async verify(resource: AttestedResource, applicationId: string, nowSeconds?: number): Promise<boolean> {
    const attestation = resource.contentAttestation;
    if (!applicationId || !resource.sourceId || !resource.resourceId ||
        !resource.contentVersion || typeof resource.content !== "string" ||
        !attestation || attestation.length > 16_000) return false;
    try {
      const fields = attestation.split(".");
      if (fields.length !== 2) return false;
      const payload = decodeBase64Url(fields[0]);
      const signature = decodeBase64Url(fields[1]);
      if (signature.length !== 64) return false;
      const claims: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload));
      if (typeof claims !== "object" || claims === null || Array.isArray(claims)) return false;
      const data = claims as SignedClaims;
      const kid = data.kid;
      if (typeof kid !== "string" || this.revokedKeyIds.has(kid)) return false;
      const trustedKey = this.keyPromises.get(kid);
      if (!trustedKey) return false;
      // WebCrypto's recent DOM typings require an ArrayBuffer-backed view,
      // while decoded typed arrays may be backed by SharedArrayBuffer.
      // Copy untrusted wire bytes into ordinary ArrayBuffers before crypto.
      const signatureBuffer = new ArrayBuffer(signature.byteLength);
      new Uint8Array(signatureBuffer).set(signature);
      const payloadBuffer = new ArrayBuffer(payload.byteLength);
      new Uint8Array(payloadBuffer).set(payload);
      if (!await crypto.subtle.verify(
        { name: "Ed25519" }, await trustedKey, signatureBuffer, payloadBuffer,
      )) return false;
      const now = nowSeconds ?? Math.floor(Date.now() / 1_000);
      if (data.v !== 1 ||
          typeof data.iat !== "number" || !Number.isSafeInteger(data.iat) ||
          typeof data.exp !== "number" || !Number.isSafeInteger(data.exp) ||
          data.iat > now + this.maxClockSkewSeconds ||
          data.exp <= now || data.exp <= data.iat || data.exp - data.iat > 3_600) return false;
      if (data.tenant !== this.tenantId || data.app !== applicationId ||
          data.source !== resource.sourceId || data.resource !== resource.resourceId ||
          data.chunk !== (resource.chunkId ?? null) ||
          data.revision !== resource.contentVersion) return false;

      const digest = new Uint8Array(await crypto.subtle.digest(
        "SHA-256", new TextEncoder().encode(resource.content),
      ));
      const hex = Array.from(digest, value => value.toString(16).padStart(2, "0")).join("");
      return data.sha256 === hex;
    } catch {
      return false;
    }
  }
}
