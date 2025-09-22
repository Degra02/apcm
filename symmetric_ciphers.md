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


# Symmetric Encryption

Pros:
- same key for enc and dec
- much faster that public key
- can be efficiently implemented directly in hardware

Cons:
- less secure -> key exchange is difficult under certain use cases over the internet
- establishing a secure channel over the internet is difficult

Used to exchange large quantities of data over the internet
Assumption: someone, magically distributed the symmetric keys between the participants -> `Delicate assumption`


E(m,k) = c
D(c,k) = m


