# R14 local regression evidence

Recorded from the final same-machine global IPv6 audit. Exit code 0 was recorded by the process wrapper. This is not an independent audit.

~~~text
PASS launcher, certificate, signed host enrollment and root proof
PASS distinct authenticated identities, identical derived epoch key
PASS signed encrypted messages, separate host authority
PASS incorrect certificate identity rejected (net::ERR_FAILED)
PASS incorrect root rejected (Incorrect room encryption key)
PASS same-name identity substitution rejected (Name is already bound to another device)
PASS guest cannot impersonate host (Invalid name or server password)
PASS replay, altered body hash, invalid signature and password-only API rejected
PASS receiver requested signed rotation; host auto-derived matching new key
PASS signed encrypted file transfer and preview
PASS 3-chunk exact download, bytes=8388925, source/receiver SHA256=04bb61438ddba67a57338af0cd6418af50855225e7f161f1da42bd5795b970ad
PASS offline/rejoin catch-up and old message/file decryption
PASS root and password absent from config
PASS R14 complete local audit
~~~

The test suite does not establish Internet reachability or independent security assurance.

## Clean repository rebuild

The portable build script initially failed when the Electron runtime download message was included in its path output. The script was corrected and the rebuilt package passed runtime import checks and the complete same-machine global IPv6 audit with exit code 0. No application source changes were needed. Electron emitted deprecated credential-storage API warnings; cross-network deployment, full HEVC and independent security review remain unverified.
