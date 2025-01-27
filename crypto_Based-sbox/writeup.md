# Based sbox

- **Category:** Crypto
- **Solves:** TBA
- **Tag:** Symmetric, Algebraic attack, XL

## Description

ChatGPT cooked a story for us:
> Once upon a time, after linear and differential cryptanalysis had revolutionized the cryptographic landscape, and before Rijndael was selected as the Advanced Encryption Standard (AES), the field of cryptography was in a unique state of flux. New cryptanalytic methods exposed vulnerabilities in many established ciphers, casting doubt on the long-term security of systems once thought to be invulnerable. In response, the U.S. National Institute of Standards and Technology (NIST) launched a competition to find a successor to the aging DES. In 2000, Rijndael was chosen, setting a new standard for secure encryption. But even as AES became widely adopted, new challenges, like quantum computing, loomed on the horizon.

## Details

The challenge is to recover the key used in a custom cipher from a single uncontrollable encryption, and send it to the server before the timer runs out. The cipher is a simple Feistel network with 7 rounds, that operates on 128-bit blocks divided into 64-bit halves. The round function is quite standard and it uses a 64-bit S-box. 

## Solution

Fix $\mathbb{F} := \mathbb{F}_{2^{64}}$ the finite field of $2^{64}$ elements with modulus $f(x) = x^{64} + x^4 + x^3 + x + 1$. Let $S: \mathbb{F} \to \mathbb{F}$ be the 64-bit S-box, which is given by the following polynomial

$$x \mapsto x^{2^{64} - 2} + c,$$

where $c \in \mathbb{F}$ is a constant.

Recal that, every finite field of size $q$, i.e. $\mathbb{F}_q$, has a cyclic group under multiplication of order $q - 1$. This means that for all $a \in \mathbb{F}_q^\ast$ we have $a^{q - 1} = 1$. In particular, $a^{q - 2} = a^{-1}$ for all $a \in \mathbb{F}_q^\ast$. Thus, the S-box can be written as

$$x \mapsto \begin{cases}
\dfrac{1}{x} + c & x \neq 0 \\
c & x = 0 
\end{cases}$$

which is a simple algebraic expression.

The Feistel network operates on 128-bit blocks divided into 64-bit halves. Let $L_i, R_i$ be the left and right halves of the block at round $i$, respectively: the initial block is $L_0, R_0$. The round function is given by

$$L_{i + 1} = R_i, \quad R_{i + 1} = L_i + S(R_i + k_{i + 1})$$

where $k_{i + 1} \in \mathbb{F}$ is the round key at round $i + 1$.

Since the key expansion uses hash functions, we can assume that the round keys are independent of each other. This means that we can recover the master key only by recovering the round keys.

The main idea is to reconstruct each encryption symbolically and then solve the system of equations that arises from these encryptions. In practice, we can
1. compute symbolically a meet-in-the-middle encryption/decryption on the plaintext/ciphertext pairs, this will give us lower-degree polynomials that represent the encryption/decryption process; and then
2. solve the system of equations that arises with Gröbner basis or XL algorithm.

Since in the actual challenge the number of rounds is 7, the system of equations will be large enough to be computationally infeasible to solve with Sagemath's Gröbner basis in time. Instead, we can use the XL algorithm with the more expensive linear algebra step implemented in C++ to solve the system of equations and recover the key in time. In particular, my solve script takes around 90 seconds to recover the key.

In truth, I think that the instance of the challenge with 7 rounds could be solved with SageMath's Gröbner basis in time if one has a powerful enough machine. However, the XL algorithm is more efficient in this kind of situation. Also, other algebraic libraries could be used to recover the key in time: in particular, Magma breaks the chall in less than 10 seconds.
