#import "./lib.typ": ieee

#import "@preview/codly:1.3.0": *
#import "@preview/codly-languages:0.1.1": *
#show: codly-init.with()
#import "@preview/tablem:0.3.0": tablem, three-line-table

#show: ieee.with(
  title: [Mirror mirror on the wall],
  authors: (
    (
      name: "Filippo De Grandi",
      department: [DISI],
      organization: [University of Trento],
      location: [Trento],
      email: "filippo.degrandi@studenti.unitn.it"
    ),
  ),
  index-terms: ("Scientific writing", "Typesetting", "Document creation", "Syntax"),
  bibliography: bibliography("refs.bib"),
  figure-supplement: [Fig.],
)

= Setup

The vulnerable environment was built using a custom Docker image based on ubuntu:18.04.
The image integrates NGINX 1.9.0 with OpenSSL 1.0.1u.

The relevant configuration files are:

/ Dockerfile:

- Compiles NGINX against OpenSSL 1.0.1f using the --with-openssl flag.
- Enables deprecated options (enable-ssl2, enable-des, enable-rc4, enable-weak-ssl-ciphers) to ensure weak cipher suites are available.
- Generates a self-signed certificate and key (512-bit RSA) with a very low security margin.
- The container exposes port 4444 for HTTPS.

/ nginx.conf:

- Enables insecure SSL/TLS versions: SSLv2, SSLv3, TLSv1, and TLSv1.2.
- Sets weak cipher suites, explicitly including RC4, DES, and aNULL ciphers.
- Disables HSTS and certificate transparency.
- Uses 512-bit DH parameters, allowing weak ephemeral key exchanges.

These configurations were intentionally designed to make the server vulnerable to a wide range of TLS attacks.

= Analysis with TLSAssistant
The nginx webserver was analyzed through the Docker version of TLSAssistant, yielding two different reports:

- full.html: Complete analysis across all modules.
- mitzvah_nomore.html: Focused analysis of RC4-related vulnerabilities.

The division in two different analysis comes from the fact that the RC4 vulnerabilities are only found if analyzed independently from the other modules.


= Results Overview

TLSAssistant identified the server as potentially vulnerable to a large number of attacks, including:

#let frame(stroke) = (x, y) => (
  left: if x > 0 { 0pt } else { stroke },
  right: stroke,
  top: if y < 2 { stroke } else { 0pt },
  bottom: stroke,
)

#tablem(
  columns: (0.6fr, 1fr, 1fr),
  align: left,
  fill: (_, y) => if calc.odd(y) { rgb("EAF2F5") },
  stroke: frame(rgb("21222C")),
)[
| Category                           | Example Vulnerabilities            | Root Cause                       |
| ---------------------------------- | ---------------------------------- | -------------------------------- |
| *Protocol Weaknesses*            | SSLv2, SSLv3 support; BEAST; DROWN | Deprecated TLS versions enabled  |
| *Cipher Weaknesses*              | Bar Mitzvah, RC4 NOMORE, Sweet32   | Use of RC4 and DES ciphers       |
| *Compression-related*            | CRIME, BREACH                      | TLS compression and gzip active  |
| *Session Issues*                 | 3SHAKE, Renegotiation attack       | Missing `extended_master_secret` |
| *HSTS / HTTPS Misconfigurations* | HSTS not set / HTTPS not enforced  | Missing security headers         |
| *Forward Secrecy*                | PFS module flagged                 | Weak DH key size (512-bit)       |
]


The Recap section in full.pdf shows most modules (e.g., BEAST, 3SHAKE, DROWN, BREACH) marked as Potentially Vulnerable.
mitzvah_nomore.pdf confirms Bar Mitzvah (CVE-2015-2808) and RC4 NOMORE vulnerabilities caused by the enabled RC4 cipher.
