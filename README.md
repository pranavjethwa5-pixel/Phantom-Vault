# PHANTOM VAULT

**Your PC is the server. Your keys. Your files. No cloud middleman.**

Why should sending a private message or sharing a massive file require somebody else's servers, somebody else's storage plan, or somebody else's permission?

Phantom Vault is a self-hosted Windows application that turns ordinary local hardware into a private messaging and file-sharing server. Connect directly over IPv6, authenticate, and exchange encrypted data. No mandatory cloud account. No third-party relay. No forced media compression.

## What we're fighting

| The problem | What Phantom Vault does instead |
| --- | --- |
| Your data lives on someone else's infrastructure. | Host it on your own PC. |
| Platforms impose file-size caps and paid storage tiers. | Transfer original files in encrypted chunks; available storage, bandwidth and implementation limits determine capacity. |
| Messaging apps downsample photos and videos. | Preserve the original bytes. A compatibility preview never replaces the original file. |
| Changing shared encryption keys can become a coordination nightmare. | Either participant can rotate the derived key; both devices synchronize automatically. |
| A password alone doesn't prove who is connecting. | Bind each enrolled name to an Ed25519 device identity and verify signed requests. |
| Self-hosting often means installing a stack of dependencies. | Build once, distribute the portable Windows folder. End users need no separate Python, Node.js or browser installation. |

## What makes this build different

- **Your hardware becomes the infrastructure.** The app detects a global IPv6 address, starts a local host and generates an invitation containing the endpoint and certificate public-key fingerprint.
- **Two separate secrets.** The server password controls admission; the user-selected 256-bit root key derives encryption keys. Receivers choose their own names and prove possession of both credentials and their device identity.
- **Verification by default.** TLS 1.3, pinned certificate identity, IP SAN and validity checks, Ed25519 signatures, SHA-256 request integrity and replay rejection. Cryptographic known-answer tests run at startup.
- **Rotate without the manual key exchange.** Signed rotation events synchronize HKDF-derived AES-256-GCM key epochs. Both sides can initiate rotation, the host can schedule it, and returning clients can recover the verified epoch history.
- **Original-quality file sharing.** Encrypted 4 MiB chunks, host approval of receiver uploads, and no compression of the transferred original. A three-chunk binary transfer passed an independent source/receiver SHA-256 comparison.
- **Portable desktop workflow.** A locally bundled interface and runtimes. HTTPS carries the API traffic; an external browser is not the application.

These are the project's design differentiators, not claims that its individual cryptographic techniques are new.

> **Experimental R14:** locally tested, not independently security-audited. The initial invitation must be trusted, the host remains trusted, and root-derived rotation is not forward secrecy. Do not rely on this build for high-risk communications.


## Architecture

- Windows desktop client using Electron, with locally bundled UI assets.
- Direct HTTPS transport over TLS 1.3 on TCP port 9543.
- Python host service, SQLite storage, 4 MiB encrypted file chunks.
- AES-256-GCM authenticated encryption; HKDF-SHA256 key epochs and per-file HKDF-SHA512 derivation.
- Ed25519 device signatures, signed requests, SHA-256 request-body checks and replay protection.
- Pinned host certificate public key, certificate validity, self-signature and IP SAN checks.
- Device private keys protected by Windows credential storage.
- Manual and optional timed rotation, with automatic epoch synchronization and historical decryption.

## Run the application

Build the portable directory using the instructions below, then copy the **entire** directory to the target 64-bit Windows computer. Launch **Phantom Vault.exe**. End users do not need to install Python or Node.js.

### Host

Choose a host name and server password (12–128 characters), generate a strong root key, and start the server. The app detects the host's global IPv6 address and creates a PV2 invitation. Share that invitation through a trusted channel; send the password and root key separately.

### Join

Paste the host invitation once, choose a name, enter the server password and root key, then connect. The invitation is saved locally. A registered name is bound to its first device identity.

Either participant can request signed key rotation. The host can configure rotation intervals. Keep the original root key for reconnecting and historical decryption.

IPv6 routing and a reachable host TCP port 9543 are required. The application does not change firewall rules automatically. Do not expose unrelated services.

## Build from source

Developer prerequisites: 64-bit Windows, Python 3.12, Node.js 24 (with npm), FFmpeg and FFprobe available on PATH. The media compatibility converter requires supported NVIDIA CUDA/NVENC hardware and drivers on the host. Ordinary messaging and file transfer do not require a discrete GPU.

From PowerShell in the repository root:

```powershell
powershell -NoProfile -File .\scripts\build-portable.ps1
```

This builds `dist\Portable` with pinned Electron and Python package versions plus the developer's locally installed Python, Node and FFmpeg runtimes. Runtime versions other than pinned packages depend on the developer's installation. Runtime downloads occur at build time, not when users launch the portable app.

To run the isolated application audit:

```powershell
powershell -NoProfile -File .\scripts\test-portable.ps1
```

Use `-GlobalIPv6` for the same-machine global-address test. Test rooms are isolated from production rooms.

## Repository layout

```text
app/                    Desktop application and host source
app/backend/            HTTPS API, crypto, vault, previews, local UI
scripts/                Portable build and isolated test commands
docs/                   Architecture, security limits and audit evidence
```

## Validation

The R14 checkpoint passed same-machine global IPv6 host/join, signed messaging, both-side rotation, reconnect and historical decryption. A three-chunk 8,388,925-byte transfer matched independently calculated SHA-256 hashes. See [audit evidence](docs/AUDIT.md).

## Security limitations

- First-contact invitation and device registration use trusted-channel / trust-on-first-use assumptions.
- Application-layer mutual authentication is not TLS client-certificate mTLS.
- Compromise of the original root key compromises derived epochs. Rotation is not forward secrecy.
- Shared credentials permit enrollment of new device names. The host remains a trusted party.
- Current epoch limit: 4,096; replacing the root requires creating a new room.
- Some media previews and large downloads explicitly authorize host-assisted file decryption.
- Full R14 HEVC playback, timed rotations, cross-network two-PC connectivity and clean-machine installation have not been independently verified.
- The executable is unsigned. See [SECURITY.md](SECURITY.md) before deployment.

Source-only repository: no user databases, certificates, private keys, invitations, or bundled runtime binaries are committed. Third-party software remains subject to its own license terms; review distribution obligations before publishing a binary release.

## License

Original source: [ISC](LICENSE). Dependencies have separate licenses; binary redistribution is not included in this source release.
