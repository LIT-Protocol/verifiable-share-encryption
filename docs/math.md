# Notation

| Name                             | Description                                                                                    |
|----------------------------------|------------------------------------------------------------------------------------------------|
| $\mathcal{C}$                    | An elliptic curve                                                                              |
| $p$                              | Field modulus in $\mathcal{C}$                                                                 |
| $q$                              | Subgroup order in $\mathcal{C}$                                                                |
| $\mathbb{G}$                     | The set of points in $\mathcal{C}$ of order $p$                                                |
| $1_{\mathbb{G}}$                 | The point at infinity                                                                          |
| $\mathbb{G}^*$                   | The set of points in $\mathcal{C}$ of order $p$ excluding the point at infinity $1_\mathbb{G}$ |
| $P$                              | Base point or generator in $\mathbb{G}^*$                                                      |
| ${\mathbb{Z}}$                   | The ring of integers modulo $q$                                                                |
| ${\mathbb{Z}}^*$                 | The ring of non-zero integers modulo $q$                                                       |
| $$\xleftarrow{\$} \mathcal{S}$$  | Uniform randomly sampled integer in $\mathbb{Z}^*$                                             |
| $\mathcal{H}_{\mathbb{Z}}$       | Hash an arbitrary length byte sequence to a value in $\mathbb{Z}^*$                            |

# Encryption

Nodes have shares $x_i$ of the secret key $x$ with a shared public key $Q = x.P$.
Nodes encrypt shares using the public encryption key $Y$. 
A threshold of $t$ nodes is required to decrypt the secret.

