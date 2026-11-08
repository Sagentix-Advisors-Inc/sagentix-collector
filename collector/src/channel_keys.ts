// The sos-app channel public keys the collector pins (apps/sos-app/docs/COLLECTOR_CHANNEL.md, section 10). sos-app signs
// its answers to the check-in, the report, the key rotation and the live connection's ack with the matching private key
// (Worker secret COLLECTOR_CHANNEL_SIGNING_KEY); an answer that names an update or a vault delivery is acted on only when
// its x-sagentix-answer-signature verifies against one of these. Raw 32-byte Ed25519 public keys, base64. A list, so the
// key can be rotated: pin the new key, release, switch the secret, then drop the old key in a later release.
//
// 2026-11-08: made with apps/sos-app/scripts/collector-channel-key.mjs on Sagentix's Mac; the private half is a 0600 file
// there, piped into `wrangler versions secret put` for each environment, and never in a repository.

export const CHANNEL_PUBLIC_KEYS: string[] = [
  "sJ5NLbDvVU2MNd4CSeNB9Vwhm68BpwdvzdQJJp5gK8Y=",
];
