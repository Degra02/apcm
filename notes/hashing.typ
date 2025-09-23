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
