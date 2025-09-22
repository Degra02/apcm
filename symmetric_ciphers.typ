= Intro

an attacker does not extract any meaning from the ciphertext -> random sequence of bits

complex to understand the plaintex that generated it, supposed to produce a digest of fixed size impossible to extract information from
> non invertibility property
> only assumed if one does not know a secret -> the key
> with the key -> very easy to invert the process and extract the plaintext

ciphertext must be inverted under the assumption that one has the key

> Key must be kept secret, cryptography is useless if the key is not protected
> anything should be public about the cipher -> NO security through obscurity


with several encryption techniques -> not only one point of failure (POF)
do not use the same key for everything


= Symmetric Encryption

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
encrypting a transaction with different fields

$ "Key is reused no more than:"  m/n > 1  "times" $

Moreover, if the same plaintext is encrypted again it should not generate the same ciphertext, distrucping regularities


Block Ciphers are a *random permutation* of bits \
Can be generated using a `RNG`

Can be described as:
- *Encryption*: Daemon checks in the left-hand column to see if it has a record of plaintext. If not, it asks the random number generator to generate a ciphertext that does not yet appear in the right-hand column, and then writes down the plaintext/ciphertext pair in the codebook and returns the ciphertext. If it does find a record, it returns the corresponding ciphertext from the right hand column
- *Decryption*: same as above but with columns swapped

The key here is the table itself, with the inconvenience that the table is large.

What is actually done is something more practical. The following structure is the same of basically every block cipher.

Organize in rounds of computations the transformation of the plaintext.
This transformation is the same in each round.\
As output, a candidate ciphertext is produced. The more rounds, the better it is because it increases confusion and diffusion.

The idea is to use a key much shorter than the number of bits in the block cipher, by using a different key at each round.

=== Confusion and Diffusion
/ Diffusion: if a plaintext bit hanges, several ciphertext bits should change\ basic demand on a block cipher, typically achieved by using linear transformations

/ Confision: Every bit of the ciphertext should depend on several bits in the key\


=== P-Box
it's a permutation of all the bits\
takes the outputs of all the S-boxes of one round, permutes the bits and feeds them into the S-boxes of the next round

A good P-box has the property that *the output bits of any S-box are distributed to as many S-box inputs as possible*

The result of this S-box - P-box transformation is *XORed* with a Key derived from the original encryption key

=== Feistel structure
uses same basic algorithm for bot henc and dec

Consista of multiple rounds of processing of the plaintext, with each round consisting of a *substitution* step *followed by a permutation* step.

In each round:
- right half of the block, R, goes through unchanged
- left half, L, goes through an operation that depends on R and enc key.
- operation carried out on the left L is referred to as the *Fesitel function F*
- the permutation step consists of *swapping* the modified *L and R*

For DES, number _n_ of rounds is 16

This permutation is one of the easiest to implement in hardware -> *Circular Shift Register*

=== Fesitel Expansion
the 32-bit right half of the 64-bit input data is expanded into a 48-bit block

Expansion permutation step
1. divide the 32-bit block into eight 4-bit words
2. attach an additional bit on the left to each 4-bit word that is the last bit of the previous 4-bit word
3. attach an additional bit to the right of each 4-bit word that is the beginning bit of the next 4-bit word

The 56-bit key is divided into two halves, each half shifted separately, and the combined 56-bit key permuted/contracted


Why exactly those numbers in the *Feistel S-Boxes*? 
It was an iterative process that ends up in those specific numbers, experience of the designers.


=== Key Scheduling

=== Diffusion & Confusion in DES
_Avalanche effect_
- if one changes one of the 64 bits in the input data block, it affects *34 bits of the ciphertext block*
- if one changes one bit of the encryption key, on the average *35 bits of the ciphertext are affected*

=== After DES: AES

== Stream Ciphers
Takes bits or bytes as input \
Were used for VOIP or Video


