# zk-Openings

- **Category:** Crypto
- **Solves:** TBA
- **Tag:** Zero-knowledge, Lattice

## Description

You will learn nothing from those openings. I can even hide an AES key in there and you wouldn't notice.

## Details

The challenge was inspired by [Plonkup](https://eprint.iacr.org/2022/086.pdf) section 4.2. The idea was to interpolate an AES key on the roots of unity of a polynomial and then use the blinding (hiding) polynomial to hide the evaluations of the polynomial. The challenge is to recover the AES key from the KZG opening of the hidden polynomial.

## Solution

Let $n$ be a length of the AES key and let $\mathbb{F}$ be a prime field of characteristic $p$ such that $\omega \in \mathbb{F}$ is a primitive $n$-th root of unity. Define $H$ to be the set of roots of unity, i.e. the multiplicative subgroup of order $n$ in $\mathbb{F}$. Let $k_0, k_1, \dots, k_{n - 1}$ be the AES key bytes, then $w(X) \in \mathbb{F}[X]$ is the polynomial such that

$$w(\omega^i) = k_i, \quad i = 0, 1, \dots, n - 1.$$

Fix $Z_H(X) = X^n - 1$, the polynomial whose roots are the elements of $H$. According to [Plonkup](https://eprint.iacr.org/2022/086.pdf), the polynomial $w(X)$ can be hidden under the discrete logarithm assumption by using a blinding (hiding) polynomial $b(X) \in \mathbb{F}[X]$ of degree $k$, where $k$ is the number of evaluations in $\mathbb{F} \setminus H$ of

$$a(X) = w(X) + b(X) \cdot Z_H(X)$$

that are disclosed. Thus, the polynomial $a(X)$ hides the evaluations of $w(X)$ in $\mathbb{F} \setminus H$ without changing its evaluations in $H$ (this is the property that makes Plonk zero-knowledge).

The main vulnerabilities of the challenge are that the polynomial $b(X)$ is of degree $k - 1$ and its coefficients are obtained from the consecutive outputs of an LCG modulo $p$. This means that
1. there is no discrete logarithm assumption that protects the polynomial $w(X)$ from being recovered from the KZG openings of $a(X)$, and 
2. there is a linear relation between all the coefficients of $b(X)$ that will make the recovery of $w(X)$ easier.

Notice that, since $w(\omega^i) = k_i$ for $i = 0, 1, \dots, n - 1$, the polynomial $w(X)$ can be written as

$$w(X) = k_0 \cdot \ell_0(X) + k_1 \cdot \ell_1(X) + \dots + k_{n - 1} \cdot \ell_{n - 1}(X),$$

where $\ell_i(X) \in \mathbb{F}[X]$ is the Lagrange polynomial such that $\ell_i(\omega^i) = 1$ and $\ell_i(\omega^j) = 0$ for $j \neq i$. Thus, each evaluation of $w(X)$ can be written as a linear combination of the $k_i$'s.

Let $x_i, y_i \in \mathbb{F} \setminus H$ be the $i$-th point of the KZG opening of $a(X)$, thus $y_i = a(x_i)$. Then we have

$$y_i = w(x_i) + b(x_i) \cdot Z_H(x_i)$$

by reordering the terms we get

$$b(x_i) = \dfrac{y_i - w(x_i)}{Z_H(x_i)}$$

where the only unknown on the right-hand side is $w(x_i)$, which can be expressed as a linear combination of the $k_i$'s.

Furthermore, since $b(X)$ is of degree $k - 1$ and we have $k$ pairs $(x_i, y_i)$, we can interpolate $b(X)$ on the points $(x_i, y_i)$, which means that we can write

$$b(X) = \sum_{i = 0}^{k - 1} b(x_i) \cdot \prod_{j \neq i} \dfrac{X - x_j}{x_i - x_j}.$$

Thus, each coefficient of $b(X)$ can be written as a linear combination of the $k_i$'s.

Let $a, c \in \mathbb{F}$ be the coefficients of the LCG, then the coefficients of $b(X)$ satisfy the linear relation

$$b_{i + 1} = a \cdot b_i + c \pmod{p}, \quad i = 0, 1, \dots, k - 2.$$

The above linear relation involves $a, c$ which are unknown to us, so we are interested in removing them from the equations, which will give us the following

$$(b_{i + 2} - b_{i + 1}) \cdot (b_{j + 1} - b_j) = (b_{i + 1} - b_i) \cdot (b_{j + 2} - b_{j + 1}) \pmod{p}, \quad i, j = 0, 1, \dots, k - 3, i \neq j.$$

Since every $b_i$ can be written as a linear combination of the $k_i$'s, we have a system of quadratic equations in the $k_i$'s. This system is underdetermined, but we know that the $k_i$'s are bytes, so each monomial in the system is bounded by $2^{16}$, which means that we could solve it using lattice reduction techniques (in fact the same techniques used in [L337tery](https://github.com/srdnlen/srdnlenctf-2023_public/tree/main/crypto_L337tery))

In the actual challenge, the $n = 32$ and $k = 20$, which means that we get $n + \binom{n + 1}{2} = 560$ monomials in the system. Thus, if we take the coefficient matrix $M$ of the system and construct the lattice

$$\begin{pmatrix} 
I & M^T \\
0 & p \cdot I
\end{pmatrix},$$

this will have dimension $(560 + 1 + 153) \times (560 + 1 + 153)$, since there are at most $\binom{k - 2}{2} = 153$ linearly independent quadratic equations in the $k_i$'s, also the $1$ is for the constant term in the equations. 

This lattice is very large, but we can further reduce its dimension by considering the right kernel matrix $K$ of $M$. Indeed, $K$ is of the form $K = (I \mid K')$. Now, consider the underdetermined solution $s$ of the system, then, by using $K$, we can modify $s$ such that all of its first $\dim(K)$ entries are zero. Let $s'$ be the modified solution with the first $\dim(K)$ entries dropped, then we can construct the lattice

$$\begin{pmatrix} 
I & K' & 0 \\
0 & s' & W \\
0 & p \cdot I & 0
\end{pmatrix},$$

where $W \in \mathbb{Z}$ is the Kannan embedding parameter. This lattice has dimension $(560 + 1) \times (560 + 1)$, which is much smaller than the previous one. By using LLL, we could find the solution of the system, but this will require a lot of time.

Instead, we use [flatter](https://github.com/keeganryan/flatter) which is basically parallelized LLL. Also, in the actual solve script, we use only a subset of the columns of $K'$, which makes the lattice even smaller. All these optimizations make the solve script run in a reasonable time: in particular, on my machine, it takes around 20 minutes.
