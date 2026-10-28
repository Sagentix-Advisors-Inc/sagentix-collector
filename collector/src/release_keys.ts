// The Sagentix release public keys a check-in `update` must verify against (apps/sos-app/docs/COLLECTOR_CHANNEL.md,
// section 4). Raw 32-byte Ed25519 public keys, base64. A list, so a key can be rotated: add the new key, release,
// then sign with it, then drop the old one in a later release.
//
// 2026-10-28: created on the release Mac; the private half lives only in its macOS Keychain (service
// `sagentix-collector-release`), and apps/sos-app/scripts/collector-channel.mjs signs with it.

export const RELEASE_PUBLIC_KEYS: string[] = [
  "Puo1SstVhUheQhkyFbepFDyLL3RYwOS4mxeSIa9Y+4E=",
];
