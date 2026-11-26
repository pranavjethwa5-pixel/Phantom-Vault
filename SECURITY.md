# Security policy

Phantom Vault R14 is experimental. It has local regression evidence, not an independent security certification or audit.

Do not publish real passwords, root keys, certificate private keys, device private keys, invitation strings, room configurations, local trust state, messages, file vaults, or unredacted diagnostics. If you discover a vulnerability, use the repository owner's private reporting channel if one is configured; otherwise contact the owner privately. Do not post credentials or exploit evidence containing real user data.

## Threat model

The host certificate's public key is pinned using the invitation. The application checks its validity, self-signature and IP SAN. Enrollment proves possession of the password, a root-derived signing identity and a separate device key. Devices are enrolled by name on first use. This does not prove the real-world identity of a person. Signed requests include body hashes, timestamps and nonces. Root-derived epoch keys preserve historical access, so compromise of the root exposes historical and future derived keys; this is not a ratchet or forward secrecy. A malicious host, compromised endpoint, copied invitation, weak password, or disclosed root secret can undermine protections. Host-assisted preview and download are not end-to-end confidential against the host.

No automatic firewall modification is performed. Keep the application and dependencies updated, restrict exposure, and use independently audited tools for high-risk communication.

## Distribution

The repository contains source, not bundled third-party executables. Review the original package metadata and dependency licenses (including FFmpeg and PyMuPDF) before distributing a portable binary or licensing the project. The original project source is released under the ISC license; this grant does not cover third-party software.
