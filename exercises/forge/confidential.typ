#import "unitn_cover.typ": unitn_cover
#import "@preview/tablem:0.3.0" : *
#import "@preview/frame-it:1.2.0" : *

#unitn_cover(
  "Advanced Programming of Cryptographic Methods",
  "Confidential But Genuine Feedback",
  "Filippo De Grandi",
  examination_day: "21/11/2025",
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
A professor (or manager) collects feedback from students (or employees). Individuals must be free to express honest opinions while maintaining anonymity. At the same time, the professor or manager must verify that submissions come only from eligible participants.

An additional fairness requirement mandates that the system must detect when multiple messages originate from the same person, without revealing the person's identity.

The system must therefore support anonymous authentication, controlled pseudonymity and duplicate detection balancing privacy, authenticity, and fairness.

= Requirements

#let (sr, fr, nfr,) = frames(
  sr: ("SR", rgb("c8d6e5")),
  fr: ("FR", rgb("d3cbd8")),
  nfr: ("NFR", rgb("dbe7d8"))
)
#let update() = counter(figure.where(kind: "frame")).update(0)

#show: frame-style(styles.hint)

== Functional Requirements

#fr[Feedback Submission][
The submitters must be able to submit feedbacks
]

#fr[Feedbacks Access][
The receivers must be able to access the feedbacks
]

#fr[Duplicate Detection Mechanism][
The receiver must be able to distinguish if two feedbacks come from the same submitter
]

== Security Requirements
#update()

#sr[Hidden Submitter Identity][
The receiver must not learn the identity of the submitter by the submitted feedbacks
]

#sr[Authorized Submission][
Only authorized submitters must be able to submit feedbacks
]

== Non-Functional Requirements
#update()

#nfr[Privacy][
The system must comply with local privacy regulations and data protection laws to securely handle each user’s data.The submitters must be aware of the inner functioning of the system
]

#pagebreak()

= Technical Details

== Architecture
// Provide an overview of the architecture of your project, e.g., by detailing the modules involved.

= Security Considerations
// Provide security considerations regarding your project. There is no fixed structure for this section, just try to reason about the security of your project (e.g., by taking inspiration from the topics dealt with during the course and adapting them to your own work, or by explicitly considering a threat model such as Dolev-Yao). This way, we will be able to understand whether you master the topics that we have presented. Try to be exhaustive and consider (at least mention) security concerns when implementing or using cryptographic primitives.
