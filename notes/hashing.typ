#import "@preview/minimal-note:0.10.0": *
#show: style-algorithm
#import "@preview/note-me:0.5.0": *
#import "@preview/showybox:2.0.4": showybox

= Hashing

#showybox(
  shadow: (
    color: black.lighten(70%),
    offset: 3pt
  ),
  frame: (
    title-color: red.darken(50%),
    border-color: black,
    body-color: red.lighten(80%)
  ),
  title: "One-way Function"
)[
Function that is easy to compute on every input, but hard to invert given the image of a random input
]

The existence of such one-way functions is still an open conjecture.

== Hash functions
A hash function is secure if:
- it is *strictly one-way*, it lets us compute the digest of a message, but does not let us figure out a message for a given digest (even very short).
- it is *computationallu infeasible to find collisions*, i.e. construct messages whose digest would equal a specified value.

== MERKLE

The input message is partitioned into _t_ number of bit blocks, each of size _n_ bits.\
If necessary, the final block is padded so that it is of the same length as others.

#figure(
  image("assets/merkl.png", width: 80%),
  caption: [Merkle],
) <fig-merkl>

Each stage of the Merkle structure takes two inputs
- the n-bit block of the input message meant for that stage
- the m-bit output of the previous stage
For the m-bit input, the first stage is supplied with a special m-bit pattern called the *Initialization Vector* (IV).\
The function _f_ that processes the two inputs, one _n_ bits long and the other _m_ bits
long, to produce an _m-bit_ output is usually called *compression function*.
- This is so since $n > m$, i.e. the output of the function f is shorter than the length of the input message segment

The compression function _f_ may involve multiple rounds of processing of the two inputs to produce the output. The precise nature of _f_ depends on what hash algorithm is being implemented

== SHA (Secure Hash Algo)
SHA refers to a family of NIST-approved cryptographic hash functions.

#figure(
  image("assets/sha_family.png", width: 80%),
  caption: [SHA hash functions],
) <fig-sha_family>

The last column refers to how many messages would have to be generated before two can be found with the same digest with a probability of 0.5.

For a secure hash algorithm that has no security holes and produces n-bit digests, one would need to come up with $2^(n/2)$ messages to discover a collision with a probability of 0.5.\
This is why the entries in the last column are half in size compared to the entries in the *Message Digest Size*.

=== SHA-1
SHA-1 is a successor to MD5 that was a widely used hash function
- There still exist many legacy applications that use MD5 for calculating digests
- This despite the fact that its usage has been deprecated as it is considered insecure

SHA-1 was cracked theoretically in the year 2005 by two different research groups. In one of these two demonstrations, it was shown how it is possible to come up with a collision for SHA-1 within a space of size 2^69 only.\ This is much less than the security level of 2^80 associated with this hash function.

#note[
  A 2013 attack breaks MD5 collision resistance in 2^18 time.\ This attack runs in less than a second on a regular computer.
In 2017, SHA-1 was broken in practice...
Full details at https://shattered.io/
]

=== Compression function
- $W_t$ contains a word of 4 bytes derived from the message block of 512 bits, i.e. 64 bytes.
- $K_t$ contains words of 4 bytes from a defined array of 64 constants.

The blue components perform the operations:
$ "Ch"(E,F,G)=(E and F) xor (not E and G) $
$ "Ma"(A,B,C) = (A and B) xor (A and C) xor (B and C) $
$ epsilon_0(A) = (A >>> 2) xor (A >>> 13) xor (A >>> 22)  $
$ epsilon_1(E) = (E >>> 6)xor (E >>> 11) xor (E >>> 25) $

The red operator is addition modulo $2^32$. The compression function is invoked in 64 rounds.
In the first round, the registers A, B, ..., H are initialized with constants

#important[
  This function contributes to performing *diffusion*.
]

#figure(
  image("assets/compression_sha1.png", width: 50%),
  caption: [Compression Function in SHA-1],
) <fig-compression_sha1>


== Application of Hash Functions

Compare possibly huge messages very efficiently by
- compute small digest
- compare digests in place of original messages
Under which assumptions this method can work?\
How does this relate to one property of the CIA triad?\
Is it enough to produce digests to check that the property is preserved or do you need to protect them in some way?\
If you need protection, which kind of protection? With the protection, do you obtain something more if the protection is properly done?\

