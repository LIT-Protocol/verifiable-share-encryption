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

Input: $Y$, $x_i$
Output: $\pi$

Steps:
- $A =$ I2OSP($x_i$)
- $\pi_{range}$ = BulletproofAggregateRangeProve($A$, $P$, $Y$, 32)
- $B = \sigma_{i < len(A)}$