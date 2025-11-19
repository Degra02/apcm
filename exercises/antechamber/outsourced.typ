#import "unitn_cover.typ": unitn_cover
#import "@preview/tablem:0.3.0" : *
#import "@preview/frame-it:1.2.0" : *

#unitn_cover(
  "Advanced Programming of Cryptographic Methods",
  "Outsourced Sensitive Database",
  "Filippo De Grandi",
  examination_day: "19/11/2025",
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

In the era of cloud computing and big data, the need for secure and efficient methods to search over cloud-hosted confidential data has become increasingly critical.
The scenario involves a client-server model, where the client is a smart device (e.g., a smartphone or IoT device) with limited computational and storage resources, and the server is a cloud service provider.
The client has sensitive data and wants to outsource it to the server. The client needs to perform search operations over this data without revealing the content of the queries or the data itself. In particular, the client must be able to:

- Add new documents to the database on the server;
- Search for keywords within the database and retrieve the relevant documents;
- Maintain privacy by ensuring that the server cannot infer information about the client's data or queries, even when updates (additions or deletions) are performed.

The server, while providing storage and computational resources, is considered semi-trusted. This means that the server is honest but curious, it will follow the protocol correctly but may attempt to learn as much as possible about the client's data and queries. For instance, the server should not link new updates to previous search queries or infer information about deleted documents.


= Requirements

#let (sr,) = frames(
  sr: ("SR", rgb("c8d6e5")),
)


#show: frame-style(styles.boxy)

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
Newly added documents must not be linkable to past queries—i.e., after a keyword has been searched, the server cannot infer that a newly added document contains that keyword.
]

#sr[Backward Privacy][
After deleting a document, the server should not be able to return it in future searches nor infer previously associated keywords.
]

=== Leakage Minimization
#sr[Search Pattern Privacy][
The server should not be able to determine whether two search tokens correspond to the same keyword.
]
#sr[Access Pattern Privacy][
The server should not learn which documents match a query (requires ORAM or PIR if desired).
]
#sr[Update Pattern Privacy][
The server must not be able to link updates (new documents, deletions) to past queries.
]

=== Integrity & Freshness
#sr[Integrity of Search Results][
The server must not omit or alter returned encrypted documents; the client must be able to verify correctness (e.g., via MACs or authenticated data structures).
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
All communication must use secure channels (TLS), despite encryption at rest.
]

=== Threat Mitigation
#sr[Resistance to Traffic Analysis][
The system should minimize information leakage through message size, timing, or frequency.
]
#sr[Compromise Containment][
If the client device is compromised, the attacker should not be able to derive the plaintext or reveal past queries (e.g., key rotation or forward-secure key updates).
]


== Functional Requirements

#counter(figure.where(kind: "frame")).update(0)
#let (fr,) = frames(
  fr: ("FR", rgb("d3cbd8")),
)

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
The client must be able to issue search queries (via encrypted search tokens) for specific keywords.
]

#fr[Result Retrieval][
The system must return a set of encrypted documents relevant to the search query.
]

#fr[Efficient Indexing][
The server must maintain an encrypted index that supports efficient search and update operations.
]

#fr[Lightweight Client Operations][
Most computation (e.g., index management, filtering) should occur server-side because the client device
is resource constrained.
]



== Non-Functional Requirements

