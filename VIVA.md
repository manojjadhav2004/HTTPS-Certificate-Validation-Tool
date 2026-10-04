# Viva Questions and Answers

## A. HTTPS, TLS and SSL

**1. What is HTTPS?**
HTTPS is HTTP running inside a TLS connection. TLS gives encryption (nobody on the path can read the data), integrity (the data cannot be changed without being noticed) and server authentication (the certificate shows who the server is).

**2. What is the difference between SSL and TLS?**
SSL (versions 2 and 3) was the original protocol from Netscape. TLS is its standardised successor (TLS 1.0 to 1.3). SSL 2.0/3.0 are broken and disabled, but people still say "SSL certificate" out of habit. Today only TLS is used.

**3. Which TLS versions are considered secure and what does the tool do?**
TLS 1.2 and 1.3. TLS 1.0 and 1.1 are deprecated. The tool gives PASS for 1.2 and 1.3 and FAIL for older versions. Python's ssl module already refuses to connect below TLS 1.2, so such a server shows up as a handshake error.

**4. What are the main improvements of TLS 1.3 over TLS 1.2?**
The handshake is shorter (1 round trip), old weak algorithms were removed (RSA key exchange, RC4, SHA-1 signatures, CBC ciphers), only forward-secret key exchange (ephemeral Diffie-Hellman) is allowed, and more of the handshake (including the certificate) is encrypted.

**5. Explain the TLS handshake in short.**
The client sends a ClientHello (versions, cipher suites, random, SNI). The server answers with its choice, its certificate and key exchange data. The client verifies the certificate (chain, dates, hostname). Both sides compute the same session keys from the key exchange, and after that all data is encrypted with fast symmetric encryption.

**6. What is forward secrecy?**
With ephemeral key exchange (ECDHE) every session uses fresh keys. If the server's private key is stolen later, old recorded traffic still cannot be decrypted.

**7. What is SNI?**
Server Name Indication: the client tells the server which hostname it wants inside the ClientHello, so one IP address can serve many HTTPS sites with different certificates. Python sends it when we pass `server_hostname`.

## B. Certificates, CA and trust

**8. What is an X.509 certificate?**
It is a standard format that binds a public key to an identity (a hostname or organisation). It contains subject, issuer, serial number, validity dates, the public key, extensions (like SAN) and the issuer's digital signature over all of that.

**9. What is a CA and a Root CA?**
A Certificate Authority is an organisation that checks the identity of a requester and signs certificates. A Root CA is a CA whose own certificate is self-signed and is placed directly in the operating system / browser trust store. Everything below it is trusted because the root vouches for it.

**10. What is a certificate chain?**
Server certificate, signed by an intermediate CA, signed by a root CA. The client builds the chain and checks every signature until it reaches a root in its trust store. Root keys are kept offline, intermediates do the daily signing.

**11. What is a trust store?**
The list of root CA certificates that a system trusts. Windows has its own certificate store, macOS the Keychain, Firefox its own list. Python on Windows loads the Windows store, so the tool trusts what Windows trusts. Anything signed by one of these roots is accepted.

**12. How does the tool handle a private CA?**
With `--ca-file root_ca.pem` the CA is added to the trust store used for that run. That is how the lab certificates (signed by our own Root CA) can be verified.

**13. What happens when a certificate is signed by an unknown CA?**
OpenSSL cannot build a chain to a trusted root (error "unable to get local issuer certificate"). The Certificate Trust check gives FAIL. This also happens behind some proxies that re-sign traffic with their own CA.

**14. What is a self-signed certificate and why is it a problem?**
A certificate signed with its own private key (subject = issuer). Nobody independent has verified it, so anyone can create one for any name. It is fine only if you trust it manually (for example, in testing). In the tool it is FAIL, or WARN if the certificate is explicitly in the trust store being used.

**15. What are the validity dates and why do certificates expire?**
`Not Before` and `Not After`. Expiry limits the damage of a stolen key, forces re-checking of identity and lets old weak algorithms disappear. Public certificates today live for about a year at most, and the limits are getting shorter. The tool gives FAIL when expired and WARN when 30 days or fewer remain.

**16. Is certificate revocation checked by this tool?**
No. Revocation (CRL, OCSP) is a limitation. The tool only checks dates, name, chain trust, key and algorithm.

**17. What is Certificate Transparency?**
Public logs where CAs record every certificate they issue, so wrongly issued certificates can be found. Browsers can require proof (SCT). Not checked by this tool.

## C. Hostname validation and SAN

**18. What is the Subject Alternative Name (SAN)?**
An extension listing all names (DNS names and IP addresses) the certificate is valid for. One certificate can cover several names.

**19. Why does the tool ignore the Common Name?**
Modern clients (RFC 6125, browsers) only use the SAN for hostname matching. The CN is legacy. A certificate without SAN fails the hostname check in the tool.

**20. How does hostname validation work and why is it needed?**
The client compares the name it connected to with the SAN entries. Without it, an attacker could present a perfectly valid certificate for `attacker.com` while you wanted `bank.com`. The chain would be fine, but the identity would be wrong.

**21. How do wildcard certificates work?**
`*.example.com` matches exactly one label on the left: `www.example.com` matches, `example.com` and `a.b.example.com` do not. The tool also rejects partial wildcards like `w*.example.com`.

## D. Cryptography

**22. How is RSA used in certificates and what key size does the tool require?**
RSA (public key cryptography based on factoring big numbers) is used for the certificate's public key and for the CA's signature. 2048 bits is the minimum accepted. Below that (for example 1024) the tool gives FAIL, because it can be attacked with enough resources.

**23. What other key types can appear?**
ECDSA (for example P-256) and Ed25519. They give similar security with much smaller keys. The tool accepts EC with 256 bits or more.

**24. What is a digital signature in a certificate?**
The CA hashes the certificate contents and encrypts/signs that hash with its private key. Anyone with the CA's public key can verify it. If a single bit of the certificate changes, verification fails.

**25. What is SHA-256 and what is the SHA-256 fingerprint?**
SHA-256 is a cryptographic hash function that gives a 256-bit digest. The fingerprint is the SHA-256 hash of the whole certificate (DER encoded). It identifies one specific certificate, and is used for manual comparison or pinning.

**26. Why is SHA-1 not accepted?**
Practical collision attacks exist (SHAttered, 2017). A fake certificate with the same hash and signature could be created. Browsers stopped trusting SHA-1 certificates, and the tool gives FAIL for SHA-1 and MD5 signatures.

**27. Does the tool implement any cryptography itself?**
No. All crypto (TLS, hashing, signature checks, key parsing) is done by OpenSSL through Python's `ssl` module and by the `cryptography` library. Writing your own crypto is unsafe.

**28. What is the difference between PEM and DER?**
DER is the binary encoding of the certificate. PEM is the same data in Base64 text with `-----BEGIN CERTIFICATE-----` lines. Python's `getpeercert(binary_form=True)` gives DER, the lab saves PEM files.

## E. Attacks

**29. What is a man-in-the-middle (MITM) attack?**
An attacker sits between client and server, reads or changes the traffic. TLS defends against it because the attacker cannot present a certificate for the target name that the client trusts, without owning the private key or getting a CA to sign it.

**30. Can this tool detect MITM attacks?**
Not in general. If the attacker's certificate chains to a root you trust (a corporate proxy, a stolen or mis-issued CA certificate, malware that installed a root), all checks pass. The tool can only show that the certificate is not the one you expected, for example by an unknown issuer or a different fingerprint.

**31. Does a SECURE verdict mean the website is safe?**
No. It means the server proved its identity for that hostname under the PKI trust model. A phishing site can have a valid certificate for its own domain. Certificate validation does not tell whether a site is honest.

## F. OpenSSL and Python

**32. What is OpenSSL?**
A widely used C library and tool that implements TLS and many crypto algorithms. Python's `ssl` module is a wrapper around it, so Python's TLS behaviour (and the error codes like "certificate has expired") come from OpenSSL.

**33. Which Python `ssl` features does the project use?**
`ssl.create_default_context()` (verification on, system trust store), `load_verify_locations()` for the lab CA, `wrap_socket(server_hostname=...)` for SNI and hostname checking, `version()` and `cipher()` for TLS details, and `getpeercert(binary_form=True)` to get the certificate.

**34. Why must verification never be disabled?**
Without verification the connection is encrypted but not authenticated; anyone can pretend to be the server. The functions `ssl._create_unverified_context()` or `CERT_NONE` remove this protection. A unit test in the project checks that the validation path does not use them.

**35. Then why does the project have a connection without verification?**
When verification fails, Python does not hand over the certificate, so the tool could not show the expired or wrong-name certificate. A separate inspection-only connection fetches it for display. It is isolated in one function, never used for the trust decision, and the report says so. The trust result always comes from the verified handshake.

**36. What does the `cryptography` library do in this project?**
It parses the DER certificate (subject, issuer, SAN, dates, public key, signature algorithm), computes the SHA-256 fingerprint, verifies the self-signature, and generates the lab certificates.

## G. About the project

**37. How is the final verdict decided?**
Any FAIL gives NOT SECURE. No FAIL but at least one WARN gives WARNING. All PASS gives SECURE. The reasons list shows every check that was not PASS.

**38. How does the lab work?**
`generate_certs.py` makes a private Root CA and six certificates (valid, near expiry, expired, wrong hostname, self-signed, weak RSA). `serve.py` runs one HTTPS server per certificate on ports 4443-4448. `lab.py` validates each one and compares the result with what is expected.

**39. Why is the expired certificate's trust check PASS?**
OpenSSL builds and checks the chain first and checks the dates afterwards. For the expired lab certificate the chain does reach the trusted Root CA; only the date is wrong, and that is reported by the Certificate Validity check. The checks are independent so each problem shows up under its own name.

**40. How does the tool handle errors like DNS failure, timeout or a closed port?**
Each case is caught and turned into a clear error message with a kind (`dns`, `timeout`, `refused`, `tls`, `network`, `invalid_input`, `ca_file`). No verdict is given because nothing could be checked, and the exit code is 3.

**41. How is user input kept safe?**
The input is limited in length, control characters and spaces are rejected, only `https://` URLs are accepted, user-info (`user@host`) is rejected, the hostname is validated label by label, the port must be 1-65535, and all network operations have a timeout. In the dashboard the browser can never send a file path, and results are shown with `textContent`, so a hostile certificate cannot inject HTML.

**42. What are the limitations of the project?**
No revocation check, no Certificate Transparency, only the leaf certificate is shown, no scanning of all supported TLS versions/ciphers, and it cannot detect MITM attacks that use a trusted CA.
