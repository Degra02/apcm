#import "unitn_cover.typ": unitn_cover
#import "@preview/tablem:0.3.0" : *
#import "@preview/frame-it:1.2.0" : *

#unitn_cover(
  "Advanced Programming of Cryptographic Methods",
  "Outsourced Sensitive Database",
  "Filippo De Grandi",
  examination_day: "27/11/2025",
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

In this scenario, a client with limited computational resources (such as a smartphone or IoT device) wishes to outsource sensitive documents to a cloud server.
The client must later search over these outsourced documents without revealing the content of either the data or the search queries.

The server is honest-but-curious: it follows protocol but attempts to infer as much information as possible.
The system must support secure document uploads, updates, deletions, and keyword searches while preventing the server from learning search patterns, access patterns, or update patterns.

Strong privacy guarantees (including forward and backward privacy) and efficient handling of encrypted data are required despite the client’s limited capabilities.

= Requirements

#let (sr, fr, nfr,) = frames(
  sr: ("SR", rgb("c8d6e5")),
  fr: ("FR", rgb("d3cbd8")),
  nfr: ("NFR", rgb("dbe7d8"))
)
#let update() = counter(figure.where(kind: "frame")).update(0)

#show: frame-style(styles.hint)

== Functional Requirements

#sr[Add documents][
The user must be able to add documents to the database
]

#sr[Delete documents][
The user must be able to delete documents from the database
]

#sr[Searching][
The database must return the documents related to the key words searched by the client.
]

#sr[User search][
The user must be able to search using key words.
]

#sr[Document keyword association][
The documents must be associated with specific keywords.
]

== Security Requirements
#update()

#fr[Non-revealing database][
The database must not leak sensitive information to the server or third-parties.
]

#fr[User scope][
The user must be able to obtain only their personal documents.
]

#fr[Data integrity][
The integrity of the information must be kept both during communication and inside the database.
]

#fr[Authentication][
The users must be authenticated before communication and for sensitive operations.
]

#fr[Secure queries][
The queries must reveal as little information as possible
]


== Non-Functional Requirements
#update()

#nfr[Compliance][
The system must comply with local regulations for sensitive data.
]

#pagebreak()

= Technical Details

== Architecture
// Provide an overview of the architecture of your project, e.g., by detailing the modules involved.
The system follows a client-server model optimized for secure outsourced storage and search functionalities.
The client (resource-limited device) performs all key-related and sensitive operations, while the cloud server stores encrypted data and executes search operations without learning their content.

=== Components
1. Client Module:
  - Generates and stores cryptographic keys.
  - Encrypts documents before uploading.
  - Creates encrypted search tokens (trapdoors) for querying.
  - Verifies search results returned by the server.

+ Server Module:
  - Stores encrypted documents and an encrypted index.
  - Processes search queries using trapdoors.
  - Returns encrypted search results to the client.
  - Maintains access logs for auditing purposes.

+ Cryptographic Module:
  - _Dynamic Searchable Symmetric Encryption_ (DSSE) @sse scheme for secure document storage and search.
  - Forward-secure key update mechanism for forward privacy.
  - Authenticated data structure for integrity verification.
  - Secure communication protocols (TLS) for data in transit.

=== Workflow
1. Upload: Client encrypts a document + keyword associations → sends ciphertext + encrypted index entries.
+ Search: Client sends trapdoor for a keyword → server performs encrypted lookup → returns encrypted matches.
+ Deletion: Client sends a deletion token referencing encrypted index entries → server removes them.
+ Integrity Check: Returned results include MACs or path proofs which the client verifies.


= Security Considerations
// Provide security considerations regarding your project. There is no fixed structure for this section, just try to reason about the security of your project (e.g., by taking inspiration from the topics dealt with during the course and adapting them to your own work, or by explicitly considering a threat model such as Dolev-Yao). This way, we will be able to understand whether you master the topics that we have presented. Try to be exhaustive and consider (at least mention) security concerns when implementing or using cryptographic primitives.

=== Confidentiality & Privacy
- DSSE ensures the server learns only minimal leakage.
- Forward privacy: New document additions cannot be linked to past queries because trapdoor keys evolve.
- Backward privacy: Deleted documents cannot be returned in future searches.
- Encrypted index: Keyword–document associations remain hidden.

=== Integrity & Authenticity
- MACs or Merkle proofs ensure the server cannot forge or alter documents.
- Authenticated channels (TLS + client keys) enforce secure communication.
- The client verifies integrity of results, protecting against server tampering.

=== Access Control
- Each client uses a unique key. The server cannot decrypt documents or impersonate users.
- Only the legitimate client can generate valid search tokens or upload/delete entries.

=== Leaks Reduction
The system mitigates:
- Search pattern leakage using probabilistic trapdoors.
- Access pattern leakage via randomized structures.
- Update pattern leakage by unlinking update tokens.

=== Threat Model
- The server is honest-but-curious as it follows protocol but tries to infer patterns.
- Even if the server stores all interactions, search tokens remain unlinkable due to the evolving trapdoor function.
- Network attackers are mitigated via TLS and standard authenticated encryption.


#bibliography("references.yml")
