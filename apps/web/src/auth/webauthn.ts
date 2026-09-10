/**
 * WebAuthn / Passkey Client Implementation (ZK-071).
 *
 * Requirements & Security Invariants:
 * - SEC-001 / SEC-002: Server authentication is strictly independent of vault encryption.
 * - Vault passphrases and Vault Keys are NEVER accepted or transmitted during WebAuthn flows.
 * - Tokens are handled in memory and passed via Bearer headers to sync APIs.
 */

export interface WebAuthnSession {
  token: string;
  sessionId: string;
  accountId: string;
  deviceId?: string;
  expiresAt?: string;
}

export interface WebAuthnRpInfo {
  name: string;
  id: string;
}

export interface WebAuthnUserInfo {
  id: string;
  name: string;
  displayName: string;
}

export interface RegisterStartResponse {
  challenge_id: string;
  challenge_b64: string;
  rp: WebAuthnRpInfo;
  user: WebAuthnUserInfo;
}

export interface LoginStartResponse {
  challenge_id: string;
  challenge_b64: string;
  rp_id: string;
}

/**
 * Converts an ArrayBuffer to a URL-safe unpadded Base64 string.
 */
export function bufferToBase64Url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Converts a URL-safe Base64 string to a Uint8Array buffer.
 */
export function base64UrlToBuffer(base64url: string): Uint8Array {
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Initiates passkey registration with the server.
 */
export async function startRegistration(
  serverUrl: string,
  options?: { username?: string; displayName?: string; accountId?: string }
): Promise<RegisterStartResponse> {
  const res = await fetch(`${serverUrl}/v1/auth/webauthn/register/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: options?.username,
      display_name: options?.displayName,
      account_id: options?.accountId,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Registration start failed with status ${res.status}`);
  }

  return res.json();
}

/**
 * Completes passkey registration with credential data.
 */
export async function finishRegistration(
  serverUrl: string,
  params: {
    challengeId: string;
    credentialId: string;
    publicKey: string;
    displayName?: string;
    deviceId?: string;
  }
): Promise<WebAuthnSession> {
  const res = await fetch(`${serverUrl}/v1/auth/webauthn/register/finish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challenge_id: params.challengeId,
      credential_id: params.credentialId,
      public_key: params.publicKey,
      display_name: params.displayName,
      device_id: params.deviceId,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Registration finish failed with status ${res.status}`);
  }

  const data = await res.json();
  return {
    token: data.session.token,
    sessionId: data.session.session_id,
    accountId: data.session.account_id,
    deviceId: data.session.device_id,
    expiresAt: data.session.expires_at,
  };
}

/**
 * Initiates passkey authentication (login) with the server.
 */
export async function startLogin(
  serverUrl: string,
  options?: { accountId?: string }
): Promise<LoginStartResponse> {
  const res = await fetch(`${serverUrl}/v1/auth/webauthn/login/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      account_id: options?.accountId,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Login start failed with status ${res.status}`);
  }

  return res.json();
}

/**
 * Completes passkey authentication (login) with assertion data.
 */
export async function finishLogin(
  serverUrl: string,
  params: {
    challengeId: string;
    credentialId: string;
    signature: string;
    deviceId?: string;
  }
): Promise<WebAuthnSession> {
  const res = await fetch(`${serverUrl}/v1/auth/webauthn/login/finish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challenge_id: params.challengeId,
      credential_id: params.credentialId,
      signature: params.signature,
      device_id: params.deviceId,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Login finish failed with status ${res.status}`);
  }

  const data = await res.json();
  return {
    token: data.session.token,
    sessionId: data.session.session_id,
    accountId: data.session.account_id,
    deviceId: data.session.device_id,
    expiresAt: data.session.expires_at,
  };
}

/**
 * Revokes an active server session.
 */
export async function revokeSession(
  serverUrl: string,
  token: string,
  sessionId?: string
): Promise<{ status: string; revokedSessionId: string }> {
  const res = await fetch(`${serverUrl}/v1/auth/session/revoke`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      session_id: sessionId,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Revocation failed with status ${res.status}`);
  }

  const data = await res.json();
  return {
    status: data.status,
    revokedSessionId: data.revoked_session_id,
  };
}

/**
 * Full browser passkey registration flow.
 * Uses navigator.credentials.create when running in browser.
 */
export async function registerPasskey(
  serverUrl: string,
  options?: { username?: string; displayName?: string; accountId?: string; deviceId?: string }
): Promise<WebAuthnSession> {
  const start = await startRegistration(serverUrl, options);

  if (typeof navigator !== "undefined" && navigator.credentials && navigator.credentials.create) {
    const challengeBuffer = base64UrlToBuffer(start.challenge_b64);
    const userIdBuffer = new TextEncoder().encode(start.user.id);

    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge: challengeBuffer.buffer as ArrayBuffer,
        rp: { name: start.rp.name, id: window.location.hostname },
        user: {
          id: userIdBuffer.buffer as ArrayBuffer,
          name: start.user.name,
          displayName: start.user.displayName,
        },
        pubKeyCredParams: [
          { alg: -7, type: "public-key" }, // ES256
          { alg: -257, type: "public-key" }, // RS256
        ],
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred",
        },
        timeout: 60000,
      },
    })) as PublicKeyCredential;

    if (!credential) {
      throw new Error("Passkey creation was cancelled or returned empty credential");
    }

    const rawId = bufferToBase64Url(credential.rawId);
    const response = credential.response as AuthenticatorAttestationResponse;
    const publicKey = response.getPublicKey
      ? bufferToBase64Url(response.getPublicKey()!)
      : bufferToBase64Url(response.attestationObject);

    return finishRegistration(serverUrl, {
      challengeId: start.challenge_id,
      credentialId: rawId,
      publicKey: publicKey || rawId,
      displayName: options?.displayName,
      deviceId: options?.deviceId,
    });
  }

  // Fallback for non-browser/test environments: generate mock credential
  const mockCredId = bufferToBase64Url(new TextEncoder().encode(`cred-${Date.now()}`));
  const mockPubKey = bufferToBase64Url(new TextEncoder().encode(`pubkey-${Date.now()}`));
  return finishRegistration(serverUrl, {
    challengeId: start.challenge_id,
    credentialId: mockCredId,
    publicKey: mockPubKey,
    displayName: options?.displayName,
    deviceId: options?.deviceId,
  });
}

/**
 * Full browser passkey sign-in flow.
 * Uses navigator.credentials.get when running in browser.
 */
export async function signInWithPasskey(
  serverUrl: string,
  options?: { accountId?: string; deviceId?: string }
): Promise<WebAuthnSession> {
  const start = await startLogin(serverUrl, options);

  if (typeof navigator !== "undefined" && navigator.credentials && navigator.credentials.get) {
    const challengeBuffer = base64UrlToBuffer(start.challenge_b64);

    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge: challengeBuffer.buffer as ArrayBuffer,
        rpId: window.location.hostname,
        userVerification: "preferred",
        timeout: 60000,
      },
    })) as PublicKeyCredential;

    if (!assertion) {
      throw new Error("Passkey assertion was cancelled or returned empty assertion");
    }

    const rawId = bufferToBase64Url(assertion.rawId);
    const response = assertion.response as AuthenticatorAssertionResponse;
    const signature = bufferToBase64Url(response.signature);

    return finishLogin(serverUrl, {
      challengeId: start.challenge_id,
      credentialId: rawId,
      signature,
      deviceId: options?.deviceId,
    });
  }

  // Fallback for non-browser/test environments
  throw new Error("WebAuthn navigator.credentials is not available in the current environment.");
}
