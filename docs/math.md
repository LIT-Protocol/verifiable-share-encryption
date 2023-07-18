# Notation

| Name                            | Description                                                                                                   |
|---------------------------------|---------------------------------------------------------------------------------------------------------------|
| $\mathcal{C}$                   | An elliptic curve                                                                                             |
| $p$                             | Field modulus in $\mathcal{C}$                                                                                |
| $q$                             | Subgroup order in $\mathcal{C}$                                                                               |
| $\mathbb{G}$                    | The set of points in $\mathcal{C}$ of order $p$                                                               |
| $1_{\mathbb{G}}$                | The point at infinity                                                                                         |
| $\mathbb{G}^*$                  | The set of points in $\mathcal{C}$ of order $p$ excluding the point at infinity $1_\mathbb{G}$                |
| $P$                             | Base point or generator in $\mathbb{G}^*$                                                                     |
| ${\mathbb{Z}}$                  | The ring of integers modulo $q$                                                                               |
| ${\mathbb{Z}}^*$                | The ring of non-zero integers modulo $q$                                                                      |
| $$\xleftarrow{\$} \mathcal{S}$$ | Uniform randomly sampled integer in $\mathbb{Z}^*$                                                            |
| $\mathcal{H}_{\mathbb{Z}}$      | Hash an arbitrary length byte sequence to a value in $\mathbb{Z}^*$                                           |
| A\[a..b\]                       | A slice of array/byte sequence `A` including the values starting at index `a` to index `b` exclusively        |
| len(A)                          | Returns the number of values in the array/byte sequence `A`                                                   |
| I2OSP                           | Integer to big endian byte sequence protocol as defined in [RFC8017](https://www.rfc-editor.org/info/rfc8017) | 
| OS2IP                           | Big endian byte sequence to integer protocol as defined in [RFC8017](https://www.rfc-editor.org/info/rfc8017) |
| a \|\| b                        | The concatenation of byte sequences a and b                                                                   |

# Encryption

Nodes have shares $x_i$ of the secret key $x$ with a shared public key $Q = x.P$.
Nodes encrypt shares using the public encryption key $Y$.
A threshold of $t$ nodes is required to decrypt the secret.

This algorithm makes use of the method **CreateBulletproofAggregateRangeProof** which computes an aggregate range proof for a set of bytes checking that each value is less than $2^{32}$ using two provided points $P$ and $Y$.

Input: $Y$, $x_i$
Output: $\pi$

Steps:
- Break the key share into bytes $A =$ I2OSP($x_i$)
- Create a range proof that each byte is $0 \le a_i < 256$ with $\pi_{range}i$ = CreateBulletproofAggregateRangeProof($A$, $P$, $Y$, 32)
- Next create El-Gamal Ciphertexts for each byte.
    - For each byte, create a blinder $$b_i \xleftarrow{\$} \mathbb{Z}^*$$ as the set $B = \{b_1, b_2, ..., b_{32}\}$
    - For each byte, create a random value $$r_i \xleftarrow{\$}\mathbb{Z}^*$$ as the set $R = \{r_1, r_2, ..., r_{32}\}$
    - Compute the El-Gamal C1 values $C1_i=b_i.P$
    - Compute the El-Gamal C2 values $C2_i=a_i.P + b_i.Y$
    - Compute the test 1 values $T1_i=r_i.P$
    - Compute the test 2 values $T2_i=C1_i+r_i.Y$
- Commitments for the Discrete Log Proof for the key share
    - Compute $Q_i = x_i.P$
    - Generate a random value $$z, z_1, z_2 \xleftarrow{\$} \mathbb{Z}^*$$
    - Compute the El-Gamal value $D_1 = z.P$
    - Compute the El-Gamal value $D_2 = Q_i + z.Y$
    - Compute $A_1 = z_1.P$
    - Compute $A_2 = z_2.Y$
    - Compute $A_3 = z_2.P$
- Compute the challenge hash that includes in the data $\mathcal{X}$
  - I2OSP(32)
  - I2OSP($i$)
  - $C1_i$
  - $C2_i$
  - $T1_i$
  - $T2_i$
  - $P$
  - $Y$
  - $D_1$
  - $D_2$
  - $Q_i$
  - $A_1$
  - $A_2$
  - $A_3$
  - $c=\mathcal{H}_{\mathbb{Z}}(\mathcal{X})$
- Compute the Discrete Log Proof
    - $\widehat{x_i}=z_1+c.x_i$
    - $\widehat{z}=z_2+c.z$
- Compute the key share byte proofs
    - $\widehat{a}_i=b_i-c.a_i$
    - $\widehat{b}_i=r_i-c.b_i$
- Ouput the amalgamated proofs and ciphertext
    - Ciphertext - $\omega = \{\{C_1\},\{C_2\}\}$
    - Proof - $\pi=\{c,\{\widehat{a}\},\{\widehat{b}\},\widehat{x_i},\widehat{z},D_1,D_2,A_1,A_2,A_3,\{\pi_{range}\}\}$

# Decryption

