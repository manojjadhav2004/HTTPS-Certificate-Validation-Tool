# HTTPS Certificate Validation Tool

A Python tool for the Cryptography and Cyber Security (CCS) subject. It connects to an HTTPS server using TLS, reads the X.509 certificate, runs seven security checks and prints a final verdict: **SECURE**, **WARNING** or **NOT SECURE**.

It comes with a command line tool, a small Flask dashboard and a local "lab" with six test certificates, so the project can be demonstrated without depending on any public website.

## 1. Project overview

When a browser opens an HTTPS site, the server sends a certificate. The browser checks that the certificate is still valid, belongs to the site, and was signed by a Certificate Authority (CA) it trusts. This project does the same checks step by step and explains each result.

The tool uses only standard security libraries: Python's `ssl` module (which uses OpenSSL) and the `cryptography` package. No cryptographic algorithm is written by hand.

## 2. Objectives

- Connect to a host over TLS and get its certificate.
- Show the certificate details (subject, issuer, serial number, validity, SAN, key, signature, fingerprint, TLS version).
- Run 7 separate checks, each giving PASS, WARN or FAIL.
- Give a final verdict with the reasons.
- Handle errors (DNS, timeout, refused connection, bad certificate) without crashing.
- Provide a local lab to demonstrate good and bad certificates.

## 3. Architecture

```
            cert_validator.py (CLI)          app.py (Flask dashboard)
                      \                          /
                       \                        /
                        validate(host, port, ca_file)
                                   |
        +--------------------------+---------------------------+
        |                          |                           |
 utils/target.py          utils/connection.py          utils/certinfo.py
 (safe input parsing)     (TLS handshake, ssl module)  (read X.509 with cryptography)
                                   |
                            utils/checks.py  -> 7 checks -> verdict
                            models.py        -> data classes / JSON

 lab/generate_certs.py  -> Root CA + 6 server certificates
 lab/serve.py           -> HTTPS servers on ports 4443-4448
 lab/lab.py             -> runs all scenarios, expected vs actual
 tests/                 -> pytest (uses the lab)
```

How one validation works:

1. The input is checked and cleaned (`utils/target.py`).
2. A normal TLS connection is made with `ssl.create_default_context()`. Certificate verification and hostname verification are **on**. This connection decides the trust result.
3. If the server certificate is refused (expired, wrong name, unknown CA ...), Python gives no certificate. So the tool opens a second, separate connection that does not verify anything. It is used **only to read and display** the certificate. Its result is never used for trust.
4. The certificate is read with the `cryptography` library and the 7 checks run.
5. Final verdict: any FAIL means NOT SECURE, otherwise any WARN means WARNING, otherwise SECURE.

### The 7 checks

| # | Check | PASS | WARN | FAIL |
|---|-------|------|------|------|
| 1 | Certificate Validity | valid, more than 30 days left | 30 days or less left | expired / not yet valid |
| 2 | Hostname Match | name found in SAN | - | name not in SAN |
| 3 | Certificate Trust | chain reaches a trusted root | - | unknown CA, self-signed, chain rejected |
| 4 | Self-Signed Check | issued by another party | self-signed but explicitly trusted | self-signed and not trusted |
| 5 | Key Strength | RSA 2048+ / EC 256+ / Ed25519 | small EC / legacy DSA | RSA below 2048 |
| 6 | Signature Algorithm | SHA-256/384/512, Ed25519 | unknown algorithm | MD5 / SHA-1 |
| 7 | TLS Version | TLS 1.2 / 1.3 | unknown | TLS 1.1 or older |

## 4. Installation on Windows 10/11

You need Python 3.11 or newer (from python.org, tick "Add python.exe to PATH" in the installer).

Open **Command Prompt** or **PowerShell** in the project folder.

### Virtual environment

```
py -3.13 -m venv venv
venv\Scripts\activate
```

(If `py -3.13` is not found, use `python -m venv venv`.) The prompt will now start with `(venv)`.

PowerShell may block the activate script. If it does, run this once and try again:

```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Install dependencies

```
pip install -r requirements.txt
```

## 5. CLI usage

```
python cert_validator.py google.com
python cert_validator.py example.com --port 443
python cert_validator.py localhost --port 4443 --ca-file lab\certificates\root_ca.pem
python cert_validator.py google.com --json
```

Options: `--port`, `--ca-file` (extra trusted CA, PEM file), `--timeout` (seconds, default 8), `--json`.

Exit codes: 0 = SECURE, 1 = WARNING, 2 = NOT SECURE, 3 = no verdict (error such as DNS failure).

Example output (shortened):

```
[PASS] Certificate Validity
[PASS] Hostname Match
[PASS] Certificate Trust
[PASS] Self-Signed Check
[PASS] Key Strength
[PASS] Signature Algorithm
[PASS] TLS Version

FINAL VERDICT: SECURE
```

## 6. Flask dashboard

```
python app.py
```

Open http://127.0.0.1:5000 in a browser, type a website (and an optional port) and press Validate. The page shows the verdict, the reasons, the 7 checks with PASS/WARN/FAIL, the certificate details and the TLS information.

For the local lab, tick "Trust the lab Root CA" or use the lab buttons (they do it for you). The lab servers must be running (see section 8).

The dashboard only listens on 127.0.0.1 so it is not reachable from other computers.

## 7. Certificate generation

```
python lab\generate_certs.py
```

This creates a private Root CA (`root_ca.pem`) and six server certificates in `lab\certificates\`. Everything is made with the `cryptography` library, so `openssl.exe` is not needed. Use `--force` to create fresh ones.

| Certificate | Port | What is special |
|-------------|------|-----------------|
| valid | 4443 | signed by the lab Root CA, 365 days |
| near_expiry | 4444 | only about 10 days left |
| expired | 4445 | expired 5 days ago |
| wrong_hostname | 4446 | only valid for `wrong.example.com` |
| self_signed | 4447 | signed by its own key |
| weak_rsa | 4448 | RSA 1024-bit key |

The near-expiry and expired certificates depend on today's date, so they are regenerated automatically when the files are older than 5 days.

The private keys in `lab\certificates\` are for this lab only. Do not use them anywhere else.

## 8. Local HTTPS servers

```
python lab\serve.py
```

Keep this window open (Ctrl+C stops it). It starts six HTTPS servers on 127.0.0.1, ports 4443 to 4448.

Run the full lab automatically (it starts the servers by itself if they are not running):

```
python lab\lab.py
```

It prints a table with the expected and the actual verdict of every scenario. Example:

```
Scenario                                  Port  Expected    Actual      Result
Valid certificate (signed by lab Root CA) 4443  SECURE      SECURE      OK
Near-expiry certificate (10 days left)    4444  WARNING     WARNING     OK
Expired certificate                       4445  NOT SECURE  NOT SECURE  OK
Wrong-hostname certificate                4446  NOT SECURE  NOT SECURE  OK
Self-signed certificate                   4447  NOT SECURE  NOT SECURE  OK
Weak RSA 1024-bit certificate             4448  NOT SECURE  NOT SECURE  OK
Valid certificate, Root CA NOT trusted    4443  NOT SECURE  NOT SECURE  OK
```

The last row uses the valid server but does not give the Root CA, to show the "unknown CA" case.

## 9. Testing

```
python -m pytest
```

The tests start the lab servers by themselves and do not need the internet or Google's certificate. They cover: valid, near-expiry, expired, hostname mismatch, self-signed, weak RSA, untrusted CA, invalid URL, unreachable server, DNS error, timeout, non-TLS server, JSON output, the Flask API, and a check that the validator never disables verification.

## 10. Demonstration procedure

Use two Command Prompt windows (both with the venv activated).

1. Window 1: `python lab\serve.py`
2. Window 2: `python lab\lab.py` - shows all scenarios, expected vs actual.
3. Window 2: show single results:
   - `python cert_validator.py localhost --port 4443 --ca-file lab\certificates\root_ca.pem` (SECURE)
   - `python cert_validator.py localhost --port 4445 --ca-file lab\certificates\root_ca.pem` (expired)
   - `python cert_validator.py localhost --port 4443` (no CA given: unknown CA)
   - `python cert_validator.py localhost --port 4448 --ca-file lab\certificates\root_ca.pem --json`
4. Window 2: `c`, open http://127.0.0.1:5000 and click the lab buttons.
5. Optional: `python cert_validator.py example.com` for a real website (needs internet).
6. `python -m pytest` to show the tests passing.

## 11. Troubleshooting

| Problem | Fix |
|---------|-----|
| `python` is not recognised | Reinstall Python and tick "Add to PATH", or use `py` instead of `python`. |
| Activate script is blocked in PowerShell | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| `ModuleNotFoundError` | The venv is not active or the install was skipped: `venv\Scripts\activate`, then `pip install -r requirements.txt`. |
| `Cannot listen on port 444x` | A lab server is already running (maybe in another window). Close it or use that one. |
| Everything says "connection refused" on 4443-4448 | `python lab\serve.py` is not running. |
| Lab results suddenly differ | Certificates are old. Run `python lab\generate_certs.py --force`. |
| Real website shows "unknown CA" | A company or college proxy may re-sign HTTPS traffic with its own CA. That is exactly what the tool reports. |
| Timeout | Check the internet connection or use `--timeout 15`. |
| Windows Firewall popup | Allow Python on private networks (lab servers use 127.0.0.1 only). |

## 12. Limitations

- A SECURE result means the certificate is valid for that host under the configured trust model (system trust store plus an optional `--ca-file`). It does **not** prove the website is trustworthy or legitimate; a phishing site can also have a valid certificate.
- The tool does **not** detect every man-in-the-middle attack. For example, if an attacker has a certificate from a CA that you already trust, all checks will pass.
- Certificate revocation (CRL / OCSP) and Certificate Transparency are not checked.
- Only the server certificate is analysed in detail; the other certificates of the chain are checked by OpenSSL but not shown.
- Only the first certificate and one TLS connection are examined, so servers that give different certificates to different clients may show different results.
- When the verified connection is refused, the certificate is read over a second connection without verification, only to display it. That second connection can in theory get a different certificate than the first one.
- TLS 1.0/1.1-only servers cannot be analysed because modern Python refuses to connect to them. They show up as a TLS handshake error.
- The dashboard connects to any host typed in, so it is meant for local use only.

## 13. Future enhancements

- Check revocation with OCSP / CRL.
- Show and check the full certificate chain (intermediate CAs).
- Check Certificate Transparency (SCT) information.
- Check supported TLS versions and cipher suites of a server.
- Export reports as PDF.
- Scan many hosts from a file.
- Warn about missing HSTS headers.

## Project structure

```
https_certificate_validator/
├── cert_validator.py     command line tool + validate() function
├── app.py                Flask dashboard
├── models.py             data classes
├── requirements.txt
├── pytest.ini
├── README.md
├── VIVA.md
├── utils/                target.py, connection.py, certinfo.py, checks.py, report_text.py, paths.py
├── web/
│   ├── templates/index.html
│   └── static/           style.css, app.js
├── lab/                  generate_certs.py, serve.py, lab.py, scenarios.py, certificates/
└── tests/
```
"# HTTPS-Certificate-Validation-Tool" 
