#import "unitn_cover.typ": unitn_cover
#import "@preview/tablem:0.3.0" : *
#import "@preview/frame-it:1.2.0" : *

#unitn_cover(
  "Advanced Programming of Cryptographic Methods",
  "Authentic Messages",
  "Filippo De Grandi",
  examination_day: "23/11/2025",
)

#let frame(stroke) = (x, y) => (
  left: if x > 0 { 0pt } else { stroke },
  right: stroke,
  top: if y < 2 { stroke } else { 0pt },
  bottom: stroke,
)

#outline()
#pagebreak()

= Description
In this scenario a user communicates with a server via Terminal User Interfaces (TUIs).

The user must register with the server and be able to send messages that cryptographically bind their identity to the message content. The server must verify both the authenticity of the sender and the integrity of each received message. It must also determine whether the user is already registered and manage key material in a quantum-resilient way.

Because adversaries may possess quantum capabilities, the system must rely on post-quantum secure cryptographic algorithms for registration, key generation, signing, and verification.

= Requirements

#let (sr, fr, nfr,) = frames(
  sr: ("SR", rgb("c8d6e5")),
  fr: ("FR", rgb("d3cbd8")),
  nfr: ("NFR", rgb("dbe7d8"))
)
#let update() = counter(figure.where(kind: "frame")).update(0)

#show: frame-style(styles.hint)

== Security Requirements
In this section, we outline the security requirements for the quantum-resistant identity-binding messaging system, focusing on post-quantum resilience, authenticity, integrity, and secure key management.

=== Quantum Confidentiality & Integrity

#sr[Post-Quantum Security][
All cryptographic primitives must be secure against quantum-capable adversaries, including signature schemes, key-exchange mechanisms, and hashing algorithms.
]

#sr[Message Integrity][
Messages sent by the user must be protected so the server can detect any tampering during transmission.
]

#sr[Identity Binding][
Each secured message must be cryptographically bound to the user’s identity in a way that is resilient to both classical and quantum attacks.
]

=== Authentication & Registration

#sr[Authenticated Registration][
The system must ensure that only legitimate users can register and obtain a valid key pair.
]

#sr[Key Ownership Proof][
Users must be able to prove ownership of the private key corresponding to their registered public key without revealing the private key.
]

#sr[Secure Key Storage][
Users and servers must securely store key material to prevent extraction by a quantum-enabled attacker.
]

=== Message Verification & Replay Protection

#sr[Sender Authenticity Verification][
The server must verify that each message is signed by the user corresponding to the registered key pair.
]

#sr[Replay Attack Resistance][
The system must detect and reject replayed valid messages to prevent malicious reuse.
]

#sr[Freshness Guarantees][
Messages must include mechanisms (timestamps, counters, or nonces) ensuring they are recent and not reused.
]

=== Communication Security

#sr[Secure Channel Establishment][
The TUI communication must be secured against eavesdropping and man-in-the-middle attacks, using post-quantum secure protocols.
]

#sr[Metadata Protection][
Communication metadata should be minimized to reduce risks of profiling by quantum-enabled adversaries.
]


== Functional Requirements

#update()

In this section, we outline the functional requirements for the identity-binding message system with post-quantum protections.

#fr[User Registration][
Users must be able to register with the server, creating or uploading a post-quantum secure public key.
]

#fr[Key Pair Generation][
Users must be able to generate a post-quantum key pair compatible with the system’s signature requirements.
]

#fr[Message Creation][
Users must be able to create messages that include both content and cryptographic bindings to their identity.
]

#fr[Message Signing][
Users must be able to digitally sign messages using a post-quantum secure signature algorithm.
]

#fr[Message Transmission][
Users must be able to send secured messages via the TUI for server verification.
]

#fr[Message Verification][
The server must verify submitted messages by checking signature validity and verifying user registration.
]

#fr[Registration Lookup][
Upon receiving a message, the server must determine whether the sender is already registered with an existing key pair.
]

#fr[Error Feedback][
The system must notify users when registration fails, verification fails, or the message format is invalid.
]


== Non-Functional Requirements

#update()

=== Performance

#nfr[Efficient Verification][
The server must verify post-quantum signatures with acceptable latency, despite their larger size compared to classical schemes.
]

#nfr[Reasonable Key Sizes][
Key generation and transmission must remain usable despite larger post-quantum key and signature sizes.
]

=== Scalability

#nfr[Support for Many Users][
The server must handle registration, key management, and message verification for a large number of users.
]

#nfr[Efficient TUI Interaction][
Operations performed through TUIs must remain efficient and responsive.
]

=== Usability

#nfr[Registration][
Users must be able to register and manage keys through a simple TUI workflow.
]

#nfr[Verification Feedback][
The system must clearly communicate success or failure conditions without exposing sensitive details.
]

=== Reliability & Availability

#nfr[High Availability][
Both message submission and verification services must remain available and robust against failures.
]

#nfr[Fault Tolerance][
Registration data and keys must be stored so they remain intact even in case of server failures.
]

=== Compliance & Governance

#nfr[Secure Audit Logging][
The system must log registration and verification events securely without exposing sensitive cryptographic material.
]

#nfr[Security Compliance][
Cryptographic choices must align with current and evolving post-quantum security standards and recommendations.
]

#nfr[Key Lifecycle][
The system must support secure key rotation, expiration, and revocation in a quantum-resilient manner.
]
