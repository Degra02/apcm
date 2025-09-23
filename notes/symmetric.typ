#import "@preview/minimal-note:0.10.0": *
#show: style-algorithm
#import "@preview/note-me:0.5.0": *
#import "@preview/showybox:2.0.4": showybox

= Symmetric

An attacker does not extract any meaning from the ciphertext $arrow$ random sequence of bits

complex to understand the plaintex that generated it, supposed to produce a digest of fixed size impossible to extract information from
- non invertibility property
- only assumed if one does not know a secret -> the key
- with the key -> very easy to invert the process and extract the plaintext

ciphertext must be inverted under the assumption that one has the key

- Key must be kept secret, cryptography is useless if the key is not protected
- anything should be public about the cipher -> NO security through obscurity


with several encryption techniques -> not only one point of failure (POF)
do not use the same key for everything

Pros:
- same key for enc and dec
- much faster that public key
- can be efficiently implemented directly in hardware

Cons:
- less secure -> key exchange is difficult under certain use cases over the internet
- establishing a secure channel over the internet is difficult

Used to exchange large quantities of data over the internet
Assumption: someone, magically distributed the symmetric keys between the participants -> `Delicate assumption`

$ E(m,k) = c $
$ D(c,k) = m $

It's a `One Way Function` under the assumption that you know a certain secret
Requirements underlying this kind of symmetric key encryption algorithm

- Block Ciphers
- Stream Ciphers

exploit the same ideas
they refer to the assumption under which the data that is taken as input is

== Block Ciphers
Takes large sets of bits
Widely used nowadays that requires heavy-duty enc and dec

Symmetric criptography is based on the assumption of _using a very fast bit operation_
Design an operation that transforms one bit of the plaintext into a bit of the ciphertext in a very efficient way

/ XOR: it's the fastest operation from the hardware point of view, and XOR can be reversed by just XORing again

I also need a stream of bits that represents the *key*
This stream *must be random*

The ciphertext can become predictable if the key is not random enough

The plaintext we are interested in exchanging usually contains different structuring inside, e.g.
encrypting a transaction with different fields:

$ "Key is reused no more than:"  m/n > 1  "times" $

Moreover, if the same plaintext is encrypted again it should not generate the same ciphertext, distrucping regularities


Block Ciphers are a *random permutation* of bits \
Can be generated using a `RNG`

One description of Block Cipher can be:
- *Encryption*: Daemon checks in the left-hand column to see if it has a record of plaintext. If not, it asks the random number generator to generate a ciphertext that does not yet appear in the right-hand column, and then writes down the plaintext/ciphertext pair in the codebook and returns the ciphertext. If it does find a record, it returns the corresponding ciphertext from the right hand column
- *Decryption*: same as above but with columns swapped

#note[The *key* here is the table itself (or _codebook_), with the inconvenience that the table is large.]

Each possible input block is one of $2^N$ integers, and each integer can specify an output N-bit block.
The codebook will be of size $N*2^N$ -> the *encryption key* for the ideal block will be of this size (huge).

=== Actual implementation
The following structure is the same of basically every block cipher.

*keyed family of pseudorandom permutations* $arrow$ for each key, a single permutation independent of all the others
Choose $2^K$ permutations uniformly at random from set of all $(2^N)!$ permutations, with $K$ the length of the keys under consideration

#important[For a block cipher to be good, an attacker should not be able to recover the key even using multiple plaintext-ciphertext pairs]

Key scheduling and rounds aim to implement *diffusion* and *confusion*.

Organize in rounds of computations the transformation of the plaintext.
This transformation is the same in each round.\
As output, a candidate ciphertext is produced. The more rounds, the better it is because it increases confusion and diffusion.

The idea is to use a key much shorter than the number of bits in the block cipher, by using a different key at each round.

=== Confusion and Diffusion
Key design principles:
- *Diffusion*: if a plaintext bit changes, several ciphertext bits should change.\ Basic demand on a block cipher, typically achieved by using linear transformations

- *Confusion*: Every bit of the ciphertext should depend on several bits in the key\

=== Substitution-Permutation Network
The simplest way to achieve both diffusion and confusion.\
Takes a block of plaintext and key as inputs and produces ciphertext block by applying several alternating *rounds* of:
- *S-boxes* and *P-boxes* that transform blocks of input bits into output bits
- commond for the transformations to be efficient operations in hardware (xor and bitwise rotation)

Key introduced in each round derived from *key schedule algorithm*

Decryption done by reversing the process

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
  title: "S-Box"
)[
  Substitutes small block of bits by another block of bits.\
  Substitution should be one-to-one $arrow$ ensure invertibility (hence decryption).\
  
  Not just a permutation of the bits:\
  A good S-Box will have the property that changing one input bit will change half of the output bits, and each output bit will depend on every input bit

]

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
  title: "P-Box"
)[
It's a permutation of all the bits.\
Takes the outputs of all the S-boxes of one round, permutes the bits and feeds them into the S-boxes of the next round

A good P-box has the property that *the output bits of any S-box are distributed to as many S-box inputs as possible*

The result of this S-box - P-box transformation is *XORed* with a Key derived from the original encryption key
]

=== DES

Adopted by NIST in 1977 $arrow$ now considered broken.\
Uses a *56-bit encryption key*.\
Uses the *Feistel cipher structure* with 16 rounds of processing.

#showybox(
  shadow: (
    color: black.lighten(70%),
    offset: 3pt
  ),
  frame: (
    title-color: black.lighten(10%),
    border-color: black,
    body-color: black.lighten(90%)
  ),
  title: "Feistel structure",
)[
Uses same basic algorithm for bot henc and dec

Consists of multiple rounds of processing of the plaintext, with each round consisting of a *substitution* step *followed by a permutation* step.

In each round:
- right half of the block, R, goes through unchanged
- left half, L, goes through an operation that depends on R and enc key.
- operation carried out on the left L is referred to as the *Fesitel function F*
- the permutation step consists of *swapping* the modified *L and R*

This permutation is one of the easiest to implement in hardware -> *Circular Shift Register*
]

#note[For DES, number _n_ of rounds is 16]


=== Fesitel Function
The 32-bit right half of the 64-bit input data is expanded into a 48-bit block

#figure(
  rect(image("assets/feistel_func.png", width: 80%)),
  caption: [Feistel Function schema],
) <fig-feistel_func>

Expansion permutation step
1. divide the 32-bit block into eight 4-bit words
+ attach an additional bit on the left to each 4-bit word that is the last bit of the previous 4-bit word
+ attach an additional bit to the right of each 4-bit word that is the beginning bit of the next 4-bit word

+ The 56-bit key is divided into two halves, each half shifted separately, and the combined 56-bit key permuted/contracted

+ The 48 bits of the expanded output produced by the Expansion permutation step are xor-ed with the round key
  - This is called key mixing
+ The output produced is broken into eight 6- bit words
+ Each six-bit word goes through a substitution step; its replacement is a 4-bit word
  - The substitution is carried out with an S-box
  - So after all the substitutions, we again end up with a 32-bit word


#figure(
  image("assets/sboxes.png", width: 80%),
  caption: [Substitution with S-boxes],
) <fig-sboxes>

#tip[
  Why exactly those numbers in the *Feistel S-Boxes*?\
  It was an iterative process that ends up in those specific numbers, experience of the designers.
]


#figure(
  image("assets/indexing_sboxes.png", width: 80%),
  caption: [Indexing the S-boxes],
) <fig-indexing_sboxes>


==== Key Scheduling
The 56-bit encryption key is represented by 8 bytes, with the least significant bit of each byte used as a parity bit
- The relevant 56 bits are subject to a permutation before any round keys are generated (see @fig-initial_permutation)
- This is called Key Permutation 1

The bit indexing is based on using the range 0-63 for addressing the bit positions in an 8-byte bit pattern in which the last bit of each byte is used as a parity bit.
- Each row has only 7 positions

The table specifies that:
- the 0th bit of the output will be the 56th bit of the input (in a 64 bit representation of the 56-bit encryption key)
- the 1st bit of the output will be the 48th bit of the input,
- ... and so on, until we have for the 55th bit of the output the 3rd bit of the input

#figure(
  image("assets/initial_permutation.png", width: 40%),
  caption: [Initial permutation],
) <fig-initial_permutation>

At the beginning of each round:
- divide the 56 key bits into two 28 bit halves
- circularly shift to the left each half by one or two bits, depending on the round, according to a table.

#note[This is to ensure that each bit of the original encryption key is used in ~14 of 16 rounds]

For generating the round key, we glue together the two halves and apply a *56 bit to 48 bit contracting permutation* (this is referred to as Permutation Choice 2) to the joined bit pattern
- The resulting 48 bits constitute the round key

_Key permutation 2_
- The bit addressing now spans the 0 through 55 index values for the 56 bit key. Out of this index range, the permutation shown above retains only 48 bits for the round key. Since there are only six rows and there are 8 positions in each row, the output will consist of 48 bits.
- As for the permutation tables above, what is shown on @fig-key_permutation2 is not a table, in the sense that the rows and the columns do not carry any special and separate meanings
- The permutation order for the bits is given by reading the entries shown from the upper left corner to the lower right corner

#figure(
  image("assets/key_permutation2.png", width: 50%),
  caption: [Key Permutation 2],
) <fig-key_permutation2>

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
  title: "Diffusion & Confusion in DES"
)[
_Avalanche effect_
- if one changes one of the 64 bits in the input data block, it affects *34 bits of the ciphertext block*
- if one changes one bit of the encryption key, on the average *35 bits of the ciphertext are affected*
]

#note[
  56-bit encryption key means *key space* of size $2^56 ≈ 7.2 * 10^16$.

  DES was broken in 1999.
]

=== After DES: AES


== Stream Ciphers
Takes bits or bytes as input \
Were used for VOIP or Video


