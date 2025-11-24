#import "unitn_cover.typ": unitn_cover
#import "@preview/tablem:0.3.0" : *
#import "@preview/frame-it:1.2.0" : *

#unitn_cover(
  "Advanced Programming of Cryptographic Methods",
  "Outsourced Sensitive Database",
  "Filippo De Grandi",
  examination_day: "20/11/2025",
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

== Security Requirements
In this section, we outline the security requirements for the outsourced sensitive database system, focusing on confidentiality, privacy, integrity, and threat mitigation.

=== Confidentialiy

#sr[Data Confidentiality][
All outsourced documents must remain encrypted at all times; the server must not be able to read document contents.
]

#sr[Query Confidentiality][
The content of search queries (keywords) must remain hidden from the server.
]

#sr[Index Confidentiality][
Metadata such as keyword-document relations must also be encrypted or obfuscated.
]

=== Forward & Backward Privacy
#sr[Forward Privacy][
Newly added documents must not be linkable to past queries, i.e., after a keyword has been searched, the server cannot infer that a newly added document contains that keyword.
]

#sr[Backward Privacy][
After deleting a document, the server should not be able to return it in future searches nor infer previously associated keywords.
]

=== Leakage Minimization
#sr[Search Pattern Privacy][
The server should not be able to determine whether two search tokens correspond to the same keyword.
]
#sr[Access Pattern Privacy][
The server should not learn which documents match a query.
]
#sr[Update Pattern Privacy][
The server must not be able to link updates (new documents, deletions) to past queries.
]

=== Integrity & Freshness
#sr[Integrity of Search Results][
The server must not omit or alter returned encrypted documents. The client must be able to verify correctness (e.g. via MACs or authenticated data structures).
]
#sr[Index Integrity][
Any tampering with the encrypted index must be detectable.
]
#sr[Freshness Guarantees][
Returned results must reflect the most recent updates (no replay of outdated search results).
]

=== Authentication & Access Control
#sr[Authorized Client Access][
Only the legitimate client may upload documents, perform searches, or request updates.
]
#sr[Secure Client–Server Communication][
All communication must use secure channels, despite encryption of data at rest.
]

=== Threat Mitigation
#sr[Resistance to Traffic Analysis][
The system should minimize information leakage through message size, timing, or frequency.
]
#sr[Compromise Resilience][
If the client device is compromised, the attacker should not be able to derive the plaintext or reveal past queries (e.g. key rotation or forward-secure key updates).
]


== Functional Requirements

#update()

In this section, we outline the functional requirements for the outsourced sensitive database system.


#fr[Document Upload][
The client must be able to upload encrypted documents to the server
]

#fr[Document Update][
The client must be able to add new encrypted documents without reuploading or re-encrypting the entire dataset.
]

#fr[Document Deletion][
The client must be able to delete previously outsourced documents in a way that prevents future retrieval.
]

#fr[Search Capability][
The client must be able to issue search queries for specific keywords.
]

#fr[Result Retrieval][
The system must return a set of encrypted documents relevant to the search query.
]

#fr[Efficient Indexing][
The server must maintain an encrypted index that supports efficient search and update operations.
]

#fr[Lightweight Client Operations][
Most computation (e.g. index management, filtering) should occur server-side because the client device
is resource constrained.
]



== Non-Functional Requirements

#update()

=== Performance
#nfr[Low Client Overhead][
Client operations must be computationally lightweight due to limited resources.
]
#nfr[Efficient Search][
Search latency must remain practical even for large datasets.
]
#nfr[Efficient Updates][
Adding or deleting documents should not require rebuilding entire encrypted indexes.
]

=== Scalability
#nfr[Scalable Storage][
The solution must support large-scale datasets.
]
#nfr[Distributed Deployment][
The server-side components should support distributed cloud infrastructure without breaking security guarantees.
]

=== Usability
#nfr[Seamless Client Experience][
Search and update operations should appear seamless to the client user.
]
#nfr[Minimal Management][
The system should automate as much of the cryptographic key management as possible.
]

=== Reliability & Availability
#nfr[High Availability][
The cloud service must maintain uptime for search and update requests.
]
#nfr[Resilience to Server Failure][
Encrypted data should survive server migrations or failures without requiring re-encryption by the client.
]

=== Compliance & Governance
#nfr[GDPR-compliant Deletion][
Deletion must make documents irrecoverable (cryptographic erasure).
]
#nfr[Audit Logging][
The system should log access, updates, and cryptographic operations in a privacy-preserving format.
]
#nfr[Regulatory Compliance][
The architecture must comply with data protection regulations depending on deployment (HIPAA, GDPR, etc.).
]

