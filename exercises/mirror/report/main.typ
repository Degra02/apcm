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
  bibliography: bibliography("refs.yml"),
  figure-supplement: [Fig.],
)

= Setup

The vulnerable environment was built using a custom Docker image based on `ubuntu:18.04`.
The image integrates `NGINX 1.9.0` with `OpenSSL 1.0.1u`. Several attempts were made to install `OpenSSL 1.0.1f`, but compilation errors prevented its use.
The use of the latter version would have allowed testing additional vulnerabilities, such as Heartbleed.

The Docker container automates also the generation of a self-signed certificate and key with very weak security parameters.

#v(4pt)

#codly(
  languages: (name: "Bash", color: rgb("#293138")),
  header: [*Certificate Generation*],
  display-icon: false
)
```bash
RUN openssl genrsa -out /usr/local/nginx/conf/server.key 512
    openssl req -new -x509 -key /usr/local/nginx/conf/server.key -out /usr/local/nginx/conf/server.crt -days 365 -subj "/C=IT/ST=Lab/L=Lab/O=TheOrgOfItalianPasta/OU=Lab/CN=pasta@italy.gov"
    chmod 600 /usr/local/nginx/conf/server.key
    openssl dhparam -out /usr/local/nginx/conf/dhparam.pem 512
```

#v(4pt)

The relevant configuration files are:

#v(4pt)

/ Dockerfile:

- Compiles NGINX against `OpenSSL 1.0.1u` using the `--with-openssl` flag.
- Enables deprecated options (`enable-ssl2`, `enable-des`, `enable-rc4`, `enable-weak-ssl-ciphers`) to ensure weak cipher suites are available.
- Generates a self-signed certificate and key (512-bit RSA) with a very low security margin.
- The container exposes port `4444` for `HTTPS`.

#v(4pt)

/ nginx.conf:

- Enables insecure SSL/TLS versions: `SSLv2`, `SSLv3`, `TLSv1`, and `TLSv1.2`.
- Sets weak cipher suites, explicitly including `RC4`, `DES`, and `aNULL` ciphers.
- Disables `HSTS` and certificate transparency.
- Uses `512-bit` DH parameters, allowing weak ephemeral key exchanges.

These configurations were intentionally designed to make the server vulnerable to a wide range of TLS attacks.

= Analysis with TLSAssistant

The `Nginx` webserver was analyzed through the Docker version of `TLSAssistant`, yielding two different reports:

- `full.pdf`: Complete analysis across all modules.
- `mitzvah_nomore.pdf`: Focused analysis of RC4-related vulnerabilities.

The division in two different analysis comes from the fact that the RC4 vulnerabilities are (strangely) only found if analyzed independently from the other modules.
They have been merged into one single `merged.pdf` for the sake of this report.


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
| Category                           | Vulnerabilities            | Root Cause                       |
| ---------------------------------- | ---------------------------------- | -------------------------------- |
| *Protocol Weaknesses*            | SSLv2, SSLv3 support; BEAST @beast; DROWN @drown | Deprecated TLS versions enabled  |
| *Cipher Weaknesses*              | Bar Mitzvah @mitzvah, RC4 NOMORE @nomore, Sweet32 @sweet32   | Use of RC4 and DES ciphers       |
| *Compression-related*            | BREACH @breach                      | TLS compression and gzip active  |
| *Session Issues*                 | 3SHAKE @3shake       | Missing `extended_master_secret` |
| *HSTS / HTTPS Misconfigurations* | HSTS not set / HTTPS not enforced  | Missing security headers         |
| *Configuration Issues* | ALPACA @alpaca | Different protocols & Multi-domain / Wildcard certificates |
]


The Recap sections in `merged.pdf` shows most modules (e.g., BEAST, 3SHAKE, DROWN, BREACH) marked as Potentially Vulnerable.
`mitzvah_nomore.pdf` confirms Bar Mitzvah (CVE-2015-2808) and RC4 NOMORE vulnerabilities caused by the enabled RC4 cipher.
