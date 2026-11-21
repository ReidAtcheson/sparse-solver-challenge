# Prover pseudocode for the signed three-band challenge

The prover takes a private binary64 solution and produces a transcript certifying an upper bound on the joint 2-norm backward error of its encoded solution. This example uses local signed receipts and the `STNPRF02` format, with RHS entries $b_i=\sigma_i/m$ and $m$ matrix rows. The first procedure ends when the authority timestamps the commitment. The second can run later. [Companion validator](VALIDATOR.md)

The first sumcheck reduces the sum of squared residuals to a residual evaluated at one random point. The second ties that value, the 128 range-test sums and the solution norm to one opening of the stamped solution.

## Commit before the clock stops

```text
COMMIT(start, pinned_authority_key, private_solution_file):
    verify the signed start with the pinned key                          # Ed25519, RFC 8032
    require profile "signed-three-band-backward80-v1"
    m = start.side                        # signed field stores number of unknowns
    require m is a power of two in [1024, 65536]
    L = log2(m)
    w = 2^floor(L/2)                      # commitment columns
    H = m / w                             # commitment rows, X[a*w + c]
    seed = SHA256("stencil-instance-seed-v1" || start)
    # The solver used this seed to generate A and b. Its algorithm is immaterial here.

    y = private_solution_file             # exactly m finite, little-endian binary64s
    M = max_j abs(y[j])                   # one streaming pass
    E = 0 if M == 0 else ceil(log2(M))   # compute from binary exponent and significand
    require -L - 30 <= E <= 54
    X(j) = round_ties_to_even(y[j] * 2^(78-E))
    # The certified coordinate is 2^(E-78) * X(j). Read and encode on demand.

    # Wahby et al., Hyrax §6.1: rectangular layout and one group commitment per row.
    # RFC 9496 defines the Ristretto255 group and its 64-byte element-derivation map.
    for c in 0 .. w-1:
        G[c] = RistrettoFromUniform(SHA512("stencil-ristretto255-generator-v1" || LE32(c)))
    for a in 0 .. H-1:
        C[a] = sum_c X(a*w + c) * G[c]    # scalar multiplication and group addition
    digest = SHA256("stencil-ristretto255-wide80-row-commitments-v1" ||
                    LE32(w) || LE32(H) || signed_LE32(E) || encode_points_in_order(C))
    save (E, C) locally
    finish = authority.stamp(start, digest)
    # The local issuer signs the attempt ID, digest, finish time and 16 fresh random bytes.
    # It records one finish per attempt. A retry of the same digest gets the same receipt.
    return finish
```

## Prove after the timestamp

In the code below, `emit` writes each item to the proof and absorbs its exact bytes into a running SHA-512 state. Initialize that state with the ASCII label `stencil-proof-transcript-v1`. A Fiat–Shamir challenge appends the single-byte role and LE32 index to a **copy** of the state and finalizes that copy. `scalar(role,i)` interprets the resulting 64 bytes as a little-endian integer modulo the Ristretto group order $q=2^{252}+27742317777372353535851937790883648493$. Sampling a challenge leaves the running state unchanged. Field elements occupy 32 canonical little-endian bytes. Strings used as hash labels exclude the terminal NUL.

```text
PROVE(start, finish, pinned_authority_key, private_solution_file, saved_E_and_C):
    verify the receipt signatures, attempt linkage, registered profile and time order
    reload E and C, require the registered exponent range and match the digest to finish.digest
    recover seed, m, L, w, H and the private X(j) view as in COMMIT
    emit("STNPRF02", start, finish)
    mask_seed = first_32_bytes(challenge_bytes('M', 0))   # take this prefix BEFORE emitting E
    emit(signed_LE32(E), encode_points_in_order(C))

    # Replay the signed three-band generator once into sparse rows.
    # Row(i) gives the cached coefficients and the public RHS sign, sigma[i].
    s = 78 - E - L
    k = 2^max(-s, 0)
    h = 2^max( s, 0)
    T[0..127] = 0
    for j in 0 .. m-1:
        bits = mask_bits(mask_seed, j)           # one 128-bit selection vector
        for t with bits[t] == 1: T[t] += X(j)   # signed integer sums
    rho = Q = 0
    for i in 0 .. m-1:
        terms, sign = Row(i)
        R_i = k * sum((aij * X(j)) for (j,aij) in terms) - h * sign
        append field(R_i) to the private scratch table R
        rho += R_i²
        Q   += X(i)²
    require Q <= m * 2^156 and every abs(T[t]) <= m * 2^78
    emit(field(rho), field(Q), signed_LE128(T[0..127]) in order)

    # Atcheson's sparse-solve construction uses norm and matvec sumchecks.
    # Here the norm check ends at a virtual residual. Only X has row commitments.
    (u, ru, _) = PRODUCT_SUMCHECK(R, R, field(rho), 'U')
    emit(field(ru))                             # ru = multilinear extension of R at u
    release residual scratch
    beta[t] = scalar('B', t) for t in 0 .. 127
    lambda  = scalar('X', 0)                    # same prefix as every beta

    # eq(u,i) is the product over bits l of u[l] if bit_l(i)=1, else 1-u[l].
    # All arithmetic from here through the opening uses the scalar field.
    P[0..m-1] = 0 on private scratch
    sigma_u = 0
    for i in 0 .. m-1:
        terms, sign = Row(i)
        sigma_u += eq(u,i) * sign
        for (j,aij) in terms: P[j] += eq(u,i) * aij
    for j in 0 .. m-1:
        mask_weight = sum_t beta[t] * mask_bits(mask_seed,j)[t]
        P[j] = k * P[j] + mask_weight + lambda * X(j)
    claim = ru + h*sigma_u + sum_t beta[t]*T[t] + lambda*Q
    (v, xv, _) = PRODUCT_SUMCHECK(X, P, claim, 'V')
    # The lambda term authenticates Q = sum X(j)² in this same product.

    split v into v_lo (first log2(w) coordinates) and v_hi (remaining coordinates)
    z[c] = sum_a eq(v_hi,a) * X(a*w + c) for c in 0 .. w-1
    emit(field(z[0]), ..., field(z[w-1]))
    check sum_c eq(v_lo,c)*z[c] == xv
    check sum_a eq(v_hi,a)*C[a] == sum_c z[c]*G[c]      # group equality
    publish the completed proof
```

The mask generator hashes `"seeded-stencil/exact-v1/range-mask" || mask_seed` with SHA-256 to get the ChaCha20 key. It uses OpenSSL's raw ChaCha20 keystream with an all-zero 16-byte IV. Coordinate $j$ consumes stream bytes $16j$ through $16j+15$, with bits numbered least significant first. Each sequential pass restarts the stream. The 128 signed sums and revealed folded row are witness-dependent information. [OpenSSL ChaCha20](https://docs.openssl.org/3.4/man3/EVP_chacha20/)

## The two sumchecks use the same loop

```text
PRODUCT_SUMCHECK(f, g, claim, role):
    # Lund, Fortnow, Karloff and Nisan: eliminate one Boolean variable per round.
    # Start with claim = sum_j f[j]*g[j]. Fold adjacent pairs, lowest index bit first.
    point = []
    for round in 0 .. L-1:
        g0 = sum_j f[2*j] * g[2*j]
        c2 = sum_j (f[2*j+1]-f[2*j]) * (g[2*j+1]-g[2*j])
        emit(field(g0), field(c2))
        r = scalar(role, round)                        # Fiat–Shamir, after both fields
        append r to point
        c1 = claim - 2*g0 - c2                         # g_round(0) + g_round(1) = claim
        claim = g0 + r*(c1 + r*c2)
        replace f and g simultaneously using new[j] = old[2*j] + r*(old[2*j+1] - old[2*j])
    check claim == f[0]*g[0]
    return (point, f[0], g[0])
```

These arrays describe the algebra. The C prover folds a single private scratch table in place. In the second sumcheck it rereads the private binary64 file for the first round and writes folded pairs back to the existing table. The three-band prover holds the packed sparse rows through the residual and transpose scans. The large scratch file peaks at $32m$ bytes on disk. Only the transcript goes to the validator. [Proof driver](protocol.c) · [Disk folds](fold.c) · [Streaming operator](operator.c) · [Row generator](matrix.c)

## Sources behind the comments

- Reid Atcheson's July design supplies the sparse-solve setting and the norm/matvec reductions. This version uses a virtual residual, the signed subset checks, and a batched solution-energy claim. [Succinct Validation of a Sparse Linear Solve](https://www.reidatcheson.com/sparse%20linear%20algebra/zero%20knowledge%20proof/validated%20computing/snark/stark/2026/07/15/validated-solution.html)
- The Boolean-cube sumcheck comes from Lund, Fortnow, Karloff and Nisan. Hash-derived public challenges follow Fiat and Shamir. The labels, encodings and message order above specify this implementation. [LFKN paper](https://lance.fortnow.com/papers/files/ip.pdf) · [Fiat–Shamir paper](https://doi.org/10.1007/3-540-47721-7_12)
- Hyrax §6.1 gives the matrix commitment and folded-row method, crediting Groth for the matrix commitment. This benchmark reveals the folded row directly. Ristretto encodes the group elements, and the optimized C commitment code uses extended Edwards arithmetic. [Wahby et al., Hyrax](https://cs.nyu.edu/~mwalfish/papers/hyrax-oakland18.pdf) · [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496.html) · [Hisil et al.](https://eprint.iacr.org/2008/522)
- The reference authority uses Ed25519 for its signed timestamps. The attempt ledger and post-commitment entropy rules belong to the benchmark. [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) · [Receipt implementation](receipt.c)
