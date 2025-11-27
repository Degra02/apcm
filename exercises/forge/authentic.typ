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
#show outline.entry.where(
  level: 1
): it => {
  set block(above: 1.2em)
  strong(it)
}

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

== Functional Requirements
#update()

#fr[Registration][
The user must be able to register to the server
]

#fr[Message Sending][
The user must be able to send a message
]

#fr[Message Receival][
The server must receive messages from users
]


== Security Requirements
#update()

#sr[Message Integrity][
The server must verify that messages have not been altered in transit
]

#sr[Quantum-level Security][
Protection against quantum capable adversaries
]

#sr[Authentication][
Authentication of users to the server
]

#pagebreak()

= Technical Details

== Architecture
// Provide an overview of the architecture of your project, e.g., by detailing the modules involved.

= Security Considerations
// Provide security considerations regarding your project. There is no fixed structure for this section, just try to reason about the security of your project (e.g., by taking inspiration from the topics dealt with during the course and adapting them to your own work, or by explicitly considering a threat model such as Dolev-Yao). This way, we will be able to understand whether you master the topics that we have presented. Try to be exhaustive and consider (at least mention) security concerns when implementing or using cryptographic primitives.
