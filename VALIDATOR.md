# Validator pseudocode for the signed 3D benchmark

The validator takes a proof byte stream, the authority’s pinned public key, and optionally the signed start received directly for the attempt. The current `signed-unit-torus-3d-backward80-v2` profile has $m$ rows and $b_i=\sigma_i/m$, where $\sigma_i=\pm1$. Its outputs are two exact integer energies, the joint 2-norm backward error, and the time from challenge release to the stamped solution commitment. The prover’s private binary64 file stays with the prover. [Companion prover pseudocode](PROVER.md)

## Check the receipts and read the claims

`read` below consumes a fixed-width value and appends its original bytes to a running SHA-512 transcript initialized with the ASCII label `stencil-proof-transcript-v1`. Integers use little-endian encoding. A field element uses 32 bytes and must encode an integer less than the Ristretto255 scalar order $q$. A failed requirement, short read, or malformed encoding rejects the proof.

```text
verify(proof, authority_key, expected_start = absent):
    require read(8 bytes) == "STNPRF02"
    start  = read(192 bytes)
    finish = read(160 bytes)
    require valid Ed25519 signatures on both receipts under authority_key
    require valid receipt tags, reserved fields, and registered signed 3D profile
    require start.time > 0 and finish.time >= start.time
    require finish.attempt == SHA256("stencil-attempt-v1" || start)
    if expected_start is present: require start == expected_start
    seed = SHA256("stencil-instance-seed-v1" || start)
    require start.side is a power of two in [32, 1024]
    m = start.side^3; L = log2(m); w = 2^floor(L/2); H = m/w

    # Fiat–Shamir. Digest a COPY of the running hash with a role byte and LE32 index.
    # The signed finish includes the stamped digest and 16 bytes of issuer entropy.
    mask_seed = first_32_bytes(digest("M", 0))      # prefix ends at the finish receipt
    E = read(signed 32-bit integer)
    require -L - 30 <= E <= 54
    s = 78 - E - L; k = 2^max(-s, 0); h = 2^max(s, 0)
    C = read(H canonical Ristretto255 points)       # one commitment per table row
    require finish.digest == SHA256("stencil-ristretto255-wide80-row-commitments-v1"
                                     || LE32(w) || LE32(H) || signed_LE32(E) || bytes(C))

    rho = read(field element)                       # claimed sum of squared integer residuals
    Q   = read(field element)                       # claimed sum of squared solution integers
    require integer(Q) <= m * 2^156
    t = read(128 signed 128-bit integers)           # subset sums of the committed X
    require abs(t[a]) <= m * 2^78 for every a
```

## Replay both sumchecks and authenticate the opening

The next block continues the same `verify` call. The two helpers implement a degree-two sumcheck. Each round sends two coefficients. The previous claim supplies the third because $g(0)+g(1)$ must equal that claim. Field arithmetic below is modulo $q$. [Lund, Fortnow, Karloff and Nisan, *Algebraic Methods for Interactive Proof Systems*](https://lance.fortnow.com/papers/files/ip.pdf) · [Fiat and Shamir, *How to Prove Yourself*](https://doi.org/10.1007/3-540-47721-7_12)

```text
    read_rounds(role):
        for j = 0 .. L-1:
            c0[j] = read(field element)
            c2[j] = read(field element)
            point[j] = little_endian_integer(digest(role, j)) mod q
        return point and the L pairs (c0, c2)

    replay(claim, rounds, point):
        for j = 0 .. L-1:
            (c0, c2) = rounds[j]
            c1 = claim - 2*c0 - c2
            claim = c0 + point[j] * (c1 + point[j]*c2)
        return claim

    # LFKN sumcheck on the square of the multilinear residual polynomial.
    u, U = read_rounds("U")
    ru = read(field element)                        # claimed residual polynomial at u
    require replay(rho, U, u) == ru^2

    # Project-specific batching. All 129 coefficients use the prefix ending at ru.
    for a = 0 .. 127: beta[a] = little_endian_integer(digest("B", a)) mod q
    lambda = little_endian_integer(digest("X", 0)) mod q
    v, V = read_rounds("V")
    z = read(w field elements)                      # one folded row
    require end of proof

    # Hyrax-style rectangular row commitments. This opening reveals z directly.
    # eq(p, i) multiplies p[j] if bit j of i is 1, else (1 - p[j]), low bit first.
    split v into its first log2(w) coordinates v_lo and remaining coordinates v_hi
    G[c] = Ristretto255_from_uniform_bytes(SHA512("stencil-ristretto255-generator-v1" || LE32(c)))
    require SUM_r eq(v_hi, r) * C[r] == SUM_c z[c] * G[c]      # group equality
    xv = SUM_c eq(v_lo, c) * z[c]                              # field evaluation of X at v
```

The matrix-shaped commitment and its row folding follow the construction described in Hyrax. This implementation reveals the folded row and subset sums. An observer learns these linear measurements of the committed solution. [Wahby et al., *Doubly-efficient zkSNARKs without trusted setup*, §6.1](https://cs.nyu.edu/~mwalfish/papers/hyrax-oakland18.pdf) · [RFC 9496, The ristretto255 and decaf448 Groups](https://www.rfc-editor.org/rfc/rfc9496.html)

## Regenerate the public endpoints and score the attempt

```text
    Auv = 0; sigma_u = 0
    for i = 0 .. m-1:
        terms, sigma_i = Row(seed, start.side, i)
        sigma_u += eq(u, i) * sigma_i
        for (j, Aij) in terms: Auv += eq(u, i) * Aij * eq(v, j)

    # Regenerate 128 subset bits per coordinate in the same order as the prover.
    key = SHA256("seeded-stencil/exact-v1/range-mask" || mask_seed)
    masks = ChaCha20_keystream(key, all_zero_16_byte_IV)
    mask_v = 0
    for j = 0 .. m-1:
        bits = next_16_bytes(masks)                 # bit a is bit (a mod 8) of byte floor(a/8)
        mask_v += eq(v, j) * SUM_a beta[a] * bits[a]

    # R = k*A*X - h*sigma. The additional lambda*X term authenticates Q.
    claim = ru + h*sigma_u + SUM_a beta[a]*t[a] + lambda*Q
    weight_v = k*Auv + mask_v + lambda*xv
    require replay(claim, V, v) == xv * weight_v

    # Rigal–Gaches joint normwise backward error. Here ||A||_2 = 7 exactly.
    # Use arbitrary-precision integers for the acceptance decision.
    a = 49*k^2*integer(Q); b = h^2*m; d = 2^106*integer(rho) - a - b
    pass = (d <= 0) or (d^2 <= 4*a*b)              # equivalent to backward_2 <= 2^-53
    relative_rhs = sqrt(rho)/(h*sqrt(m))            # displayed approximations
    backward_2   = sqrt(rho)/(7*k*sqrt(Q) + h*sqrt(m))
    status = CERTIFIED_PASS if pass else CERTIFIED_MISS
    return status, rho, Q, relative_rhs, backward_2, finish.time - start.time
```

The score is the least common relative perturbation to $A$ and $b$ that makes the encoded solution exact, allowing unstructured perturbations in the 2-norm. A valid proof above threshold is a **certified miss**. [Higham, *Testing Linear Algebra Software*, §2.1, giving the Rigal–Gaches formula](https://nhigham.com/wp-content/uploads/2023/10/high97t.pdf)

**Why integer scoring works.** The project’s subset test gives a loose centered-coordinate bound $|X_j|\le 2m2^{78}$ except with the range test’s soundness error. For a committed out-of-range coordinate, toggling its inclusion bit separates the two possible sums enough that at most one can pass. Under the independent random-mask model, 128 tests give error at most $2^{-128}$ for that fixed vector. The implementation expands the signed-receipt challenge pseudorandomly. With $m\le2^{30}$, this bound makes the true $Q\le2^{248}<q$. The explicit check then gives $Q\le m2^{156}$. Since $k\le64$, $h\le2^{108}$, and $\|A\|_2=7$, the ordinary residual norm is at most $7k\sqrt Q+h\sqrt m<2^{124}$. Both authenticated field energies therefore lift to integers, subject to the proof’s commitment, sumcheck and Fiat–Shamir assumptions. [Implementation and soundness discussion](REFERENCE.md#transcript-and-soundness-assumptions)

**Validator resources.** Factor each equality weight into high- and low-index tables of sizes $H$ and $w$. The validator streams the generated rows once and the masks once, uses $O(\sqrt m)$ working memory, and reads the folded row from the proof. [C verifier](protocol.c) · [Public endpoint scan](operator.c)
