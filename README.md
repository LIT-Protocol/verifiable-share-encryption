# Verifiable Share Encryption

Verifiable Encryption was first proposed by Jan Camenisch and Victor Shoup in [2003](https://www.shoup.net/papers/verenc.pdf). 
A rust [crate](https://crates.io/crates/verenc) exists for this implementation. 
An alternative approach uses El-Gamal encryption with discrete log proofs where the decrypter must solve the D-LOG to find the original value. 
This works as long as the encrypted value is not too small. 
If larger, the value can be partitioned into smaller chunks where solving the D-LOG is quick. 
There is also a [lattice based one](https://eprint.iacr.org/2017/122.pdf) but the performance has not been measured.

The goal for encryption of PKPs is to prove the ciphertext encrypts the signing key share corresponding to a specific verification key. 
For example, when an encrypted backup $B$ with encryption key $K$ for Alice whose signing key is $a$ and verification key is $A = a.P$, the proof can be verified calling $verify(A, B, K)$.
Verify returns true if the backup is the encrypted signing key that corresponds to the verification key.

## Camenisch-Shoup

Camenisch-Shoup (CS) verifiable encryption uses groups of unknown order using which means creating a group that is the product of two prime numbers like RSA or using class groups. 
Groups that are the product of two primes can be broken with PQ computes and are much slower than elliptic curves. 
Class groups are considered PQ safe but are complicated to find and slow in practice.

## El-Gamal

El-Gamal can work with any groups including elliptic curves. 
The base encryption works by creating a keypair $k, K = k.P$, and creating a ciphertext by computing

$$r \xleftarrow{\$} \mathbb{Z}_q$$
 
$$Q \xleftarrow{\$} \mathbb{G}$$

$$C_1 = r.P$$

$$C_2 = a.Q + r.K$$

$$B = \{C_1, C_2\}$$

Thus the ciphertext is around 2Kb and an accompanying proof is around 3.1Kb.

## Implementation

This crate uses El-Gamal encryption with DLOG proofs but encrypt each byte such that the DLOG can be solved easily to restore the key. 
Without this step it will be impossible to restore the key. 
However, this necessitates using bulletproofs to prove each byte is less than $2^8$. 
Luckily, bulletproofs allows proof aggregation to shrink the proof.