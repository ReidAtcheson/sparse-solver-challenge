# Soundness of the timestamped residual certificate

For the shared-exponent C proof, a classical random-oracle analysis bounds adaptive grinding across both sumchecks and the batching step. The folded opening also admits a witness extractor. It rewinds a prover to its digest request, obtains independent accepted openings in simulated continuations, and solves a linear system for the stamped vector. The public validator still reads a single transcript. This is a conditional argument for the implemented message order. Its extraction cost matters to any claim about concrete bits of security. [Verifier pseudocode](VALIDATOR.md) · [C verifier](protocol.c)

The analysis below models the local Ed25519 issuer in versions 1 and 2. Version 3 pins a winning digest before a shared Quicknet round and authenticates time with RFC 3161. Its registrar and shared-beacon assumptions are specified separately. [External receipt security model](BEACON.md#wire-format-and-trust-inputs)

The three-band challenge uses the same message order, challenge derivation and commitment opening. Its generator-specific bounds lift the two authenticated field energies to ordinary integers and give a conservative test for backward error. [Three-band integer bounds](THREE_BAND_PROOF.md)

## What counts as a forgery

Fix a registered start and an independently pinned issuer key. Permit one freshly sampled finish receipt for the attempt and take probabilities over its unrevealed randomness. The adversary may choose the digest, use the genuine issuer, abort selectively, and make adaptive classical hash queries. It wins the numerical game if the verifier certifies a transcript, including a certified miss, and the energies disagree with those of the vector recovered from the prover's state at the digest request. Count an accepted proof for which extraction fails as a win too. A false pass is a special case. Substituting an unauthorized receipt is a separate authentication failure included in the overall bound below.

For signed 3D the witness is an exponent $E$ and a table $X$ of field elements, interpreted by their centered integer representatives. The physical solution is $x=2^{E-78}X$. Let $n=2^L$, let $\sigma_i\in\{-1,1\}$ be the public RHS codes, and put $s=78-E-L$, $k=2^{\max(-s,0)}$, $h_b=2^{\max(s,0)}$. The asserted values are

$$
Q_*=\sum_j X_j^2,\qquad R=kAX-h_b\sigma,\qquad \rho_*=\sum_i R_i^2 .
$$

The same proof covers the July comparison with its registered integer matrix and RHS codes. Its joint backward error is a certified upper bound. The signed 3D profile uses the exact matrix 2-norm and an exact integer pass decision. These assertions concern the scaled vector. Identifying a particular input file, solver, or execution history would require additional evidence. The older one-energy wire format is outside the theorem below. [Scoring code](protocol.c) · [Comparison profile](benchmarks/blog-comparison/README.md)

## The folded opening and binding

Write $w=2^{\lfloor L/2\rfloor}$ for the commitment width and $h=n/w$ for its height. The digest binds the shape, exponent, and ordered canonical encodings $C_i$. Each row commits as $C_i=\sum_jX_{ij}G_j$. At the final point $v$, let $e_i=\operatorname{eq}(v_{\rm hi},i)$ be the multilinear interpolation weights of the rows. The prover reveals $z$, and the validator checks $\sum_i e_i C_i=\sum_j z_jG_j$. It obtains the scalar endpoint by taking the dot product of $z$ with the low-coordinate weights. [Digest and group check](commit.c) · [Hyrax, §6.1, for the row-folding construction](https://cs.nyu.edu/~mwalfish/papers/hyrax-oakland18.pdf)

If $X$ opens the rows, a passing $z$ different from $z^*_j=\sum_i e_iX_{ij}$ immediately gives a **nonzero scalar relation** among the public bases.

$$
\sum_j (z_j-z^*_j)G_j=0 .
$$

This implication holds for every adaptively selected $v$. The computational assumption is that finding such a relation among the actual hash-derived Ristretto255 generators is hard, accounting for preprocessing against the fixed bases. For independent uniform group generators this is justified by a discrete-log reduction. Given $P,D=dP$, sample bases $G_j=a_jP+b_jD$ with independent uniform $a_j,b_j$. A nonzero output relation recovers $d$ except when its dot product with the hidden $b$ vector vanishes, an event of probability $1/q$. Applying that argument to the concrete fixed hash-to-group setup needs a suitable setup model. [Generator derivation](commit.c) · [Ristretto255](https://www.rfc-editor.org/rfc/rfc9496.html#section-4)

## Adaptive Fiat–Shamir soundness for a fixed opening

First fix a genuine row opening $X$, independently of the fresh receipt randomness. Treat the transcript challenge domain of SHA-512 as a classical random oracle. Each scalar is a 512-bit output reduced modulo the group order $q$, giving maximum point probability $\mu=\lceil 2^{512}/q\rceil/2^{512}$. Let $J$ bound the adversary's distinct transcript challenge queries in the real continuation. The verifier may finish one proof even when the adversary never asked for its last challenges. [Challenge generation](protocol.c) · [Scalar field](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.4)

1. **Norm sumcheck.** At any round there is a true remaining sum and a true degree-at-most-two round polynomial for $X$. If the current claim is false, the sent polynomial must differ from the true one because the sum of its values at 0 and 1 equals the false claim. It can restore the true claim at at most two values of the next challenge. That costs at most $2\mu$. If a false $\rho$ survives every round without such a restoration, passing the square check forces the claimed residual endpoint $r_u$ to differ from the true one.
2. **Batching.** At the prefix ending in $r_u$, the discrepancies in that endpoint, the 128 subset sums and $Q$ are fixed. The combined discrepancy equals $\Delta r_u+\sum_a\beta_a\Delta t_a+\lambda\Delta Q$. If any slope is nonzero, conditioning on the other coefficients gives probability at most $\mu$ of cancellation. A nonzero constant with all slopes zero cannot cancel. This also authenticates the sign of the residual endpoint left ambiguous by the square.
3. **Matvec sumcheck.** Write tildes for multilinear extensions and $M_a$ for the public subset masks. The round polynomial comes from summing $\widetilde X(t)(k\widetilde A(u,t)+\sum_a\beta_a\widetilde M_a(t)+\lambda\widetilde X(t))$ over the Boolean column index. Its Boolean sum is the true residual endpoint plus $h_b\widetilde\sigma(u)$ and the true weighted projections and solution energy. The product has individual degree at most two. A false batched claim can be restored with probability at most $2\mu$ per round. Otherwise its final value disagrees with the authentic opening and the verifier's independently generated matrix, RHS and mask endpoints. [Public endpoint scan](operator.c)

To count adaptive retries, consider the tree of all well-formed prefixes for this receipt. When the adversary asks for a deep prefix first, the proof of the bound privately samples any missing ancestor challenges in order, then answers only the requested query. At the batching prefix it privately samples all 129 distinct, role-separated outputs together, even if only one is requested. The joint law of the oracle answers is unchanged. Fixed widths and the final role/index suffix give each valid query a unique interpretation for this start. The simulation leaves a previously sampled node alone. Thus the incoming state of each new round is fixed before its fresh challenge, even for a prover that guesses later messages first.

Each query introduces at most one path with $2L$ quadratic rounds and one batching event. Add one path for verification. A union bound on restorations anywhere in these paths gives the conservative **field error**

$$
\epsilon_{\rm field}\le (J+1)(4L+1)\mu .
$$

This counts abandoned prefixes and shared prefixes. It allows arbitrary branching across rounds. It holds for any given mask matrix and charges a false folded opening separately to the group relation assumption. The prefix argument is specific to this serialization. General multi-round Fiat–Shamir transforms can have different losses. [Round-by-round soundness](https://eprint.iacr.org/2018/1004) · [Attema, Fehr and Klooß on multi-round Fiat–Shamir](https://eprint.iacr.org/2021/1377)

## Extracting the vector at the stamp request

The issuer receives a 32-byte digest. Collision resistance binds two revealed row tuples to the same digest computationally. By itself it supplies no row scalars. The following black-box extractor obtains those scalars for a prover with appreciable acceptance probability.

1. Save the classical prover state just after it requests a stamp and before the issuer releases the finish receipt. In each private simulation, resume from that state with a newly issued finish for the same request. Preserve the start, signing key, group generators, common row-digest function, and all oracle answers from before the checkpoint. Use private copies for future answers in the transcript and mask-key domains and sample fresh issuer coins. Keep only proofs accepted for the exact receipts of that simulation. The security reduction generates the honest issuer and can fork its state. All these signatures are internal to the proof of security. The live issuer issues one receipt.
2. From each accepted continuation retain its row weights $e$, folded row $z$, and row tuple. Two different tuples, including different exponents, produce a SHA-256 collision because they verify against the same request. Subject to that failure event, all accepted continuations use the same $E,C$.
3. Collect $h$ linearly independent weight rows. Stack them into $W$ and the corresponding openings into $Z$. Every group check says $WC=ZG$. Invert $W$ over the scalar field and set $X=W^{-1}Z$. Linearity in the prime-order group gives $C_i=\sum_j X_{ij}G_j$ for **every stamped row**. This argument handles arbitrary valid row points supplied by the prover. It needs no declaration of how the prover constructed them.
4. Run the real numerical check in a separate, fresh continuation from the saved state. The extracted $E,X$ are fixed for this continuation before its receipt, masks, and sumcheck challenges. A conflicting tuple gives a digest collision. An inconsistent folded row gives the nonzero group relation above. Distinct successfully extracted matrices for the same tuple would also give a relation by subtracting a row.

**Why independent rows arrive.** For any proper span $S$ of weight rows collected so far, choose $a\ne0$ perpendicular to $S$. The polynomial $P(t)=\sum_i a_i\operatorname{eq}(t,i)$ is nonzero since its Boolean evaluations are the entries of $a$. If the next weight row lies in $S$, then $P(v_{\rm hi})=0$. Along the $\ell=\log_2 h$ high-coordinate challenges, a nonzero remaining multilinear polynomial can become identically zero at at most one choice of its next coordinate. Apply the same prefix-tree count, keeping $S$ fixed before this independent continuation. The probability of producing an accepted row in $S$ is at most

$$
\kappa=(J+1)\ell\mu+\epsilon_{\rm early},
$$

where $J$ also bounds queries per simulated continuation. Here $\epsilon_{\rm early}$ covers a real future receipt prefix already queried at the checkpoint. With a fresh uniform 128-bit finish nonce and $J_0$ prior candidate prefixes for the specified attempt, $J_0/2^{128}$ suffices. This argument tolerates a prover who aborts on inconvenient challenges.

**Extraction cost.** Choose $\tau>\kappa$ and failure tolerance $0<\zeta<1$. At a saved state with acceptance probability at least $\tau$, each continuation supplies a new independent row, or a digest collision, with probability at least $\tau-\kappa$. Allow $\lceil\ln(h/\zeta)/(\tau-\kappa)\rceil$ trials per rank increase. The chance of exhausting the budget before full rank is at most $\zeta$. States with acceptance probability below $\tau$ contribute at most $\tau$ to the joint probability of extraction failure and real acceptance. Straightforward inversion and recovery take $O(h^3+h^2w)$ field operations after the forks. This is a polynomial extractor for nonnegligibly successful classical provers under the usual scaling of the security parameters. At $128^3$ it needs **2,048 independent accepted rows**. A phone running the actual protocol needs just one.

## Range masks and integer semantics

Let $T=n2^{78}$. For a fixed extracted $X$ with an offending centered coordinate of magnitude greater than $2T$, hold the other inclusion bits fixed. Toggling that coordinate moves the sum by centered modular distance greater than $2T$, so at most one of the two sums fits in $[-T,T]$. With independent uniform masks, all 128 **true** sums fit with probability at most $2^{-128}$. Choosing one offending coordinate suffices for the whole vector. False transmitted sums were covered by the batching and field proof.

The implementation expands 16 bytes per coordinate with ChaCha20. The seed is derived from the signed receipt and becomes public. The computational comparison concerns only the event that the *true sums of the already-fixed $X$* all fit. A stream distinguisher can test this event using $X$ and the challenge stream alone. Under a fresh uniform effective key independent of $X$, its excess over $2^{-128}$ is bounded by a ChaCha20 distinguishing advantage for $16n$ bytes, including the cost of obtaining $X$. Publishing the key prevents a wholesale replacement of the entire proof transcript with a secretly random stream. In the oracle model the fresh receipt gives a new mask seed and a domain-separated SHA-256 derivation gives its key. Charge a prequeried receipt prefix to $\epsilon_{\rm early}$ and a prequeried key-derivation input to at most $K_0/2^{256}$ for $K_0$ previously fixed guesses at the fresh 256-bit seed. Offline proof retries with the same receipt share those masks. [Mask derivation and stream layout](mask.c)

Outside the range failure event, $|X_j|\le 2T$ makes $Q_*\le n(2T)^2\le2^{248}<q$. Its authenticated field representative is therefore its ordinary integer value. The verifier enforces $Q_*\le n2^{156}$, giving $\|X\|_2\le2^{93}$. For signed 3D, $k\le64$, $h_b\le2^{108}$, $\|\sigma\|_2=\sqrt n$, and $\|A\|_2=7$. Hence $\|R\|_2\le7k2^{93}+h_b\sqrt n<2^{124}$. For July, the integer matrix has norm at most 10, $k=1$, $h_b\le2^{100}$, and each RHS code has magnitude at most 207, yielding the same upper bound. In either case $\rho_*<2^{248}<q$. This proves exact integer energies even on a certified miss. The proof enforces a looser coordinate bound than the honest 80-bit encoder uses. [Profile bounds and endpoint checks](VALIDATOR.md) · [July integer units](benchmarks/blog-comparison/README.md)

## Combined security statement

For one specified attempt and one submitted proof, the joint probability of acceptance with failed extraction, an incorrect integer score, or unauthorized receipts is bounded in the stated classical model by

$$
\tau+\zeta+(J+1)(4L+1)\mu+2^{-128}
+\epsilon_{\rm fresh}+\epsilon_{\rm stream}
+\epsilon_{\rm receipt}+\epsilon_{\rm digest}+\epsilon_{\rm relation}.
$$

Here $\epsilon_{\rm fresh}$ covers the real continuation's receipt and key-derivation prequeries. The simulated rank trials account for their receipt prequeries in $\kappa$. The last four computational terms charge the stream event, receipt authentication, a collision in the common row-digest function, and a nonzero generator relation. The advantages must be evaluated at the resource budget of the corresponding reduction, **including simulated continuations and extraction**. The inequality gives a family of time/error tradeoffs through $\tau,\zeta$. Substituting $2^{-128}$ for the entire right-hand side would discard those costs.

The model assumes a trusted issuer with fresh entropy, durable first issuance and an isolated rewindable prover whose collaborators are included in its saved state. The group setup and the digest function are common across all simulated worlds. The transcript oracle and mask-key derivation preserve their pre-stamp answers and can be simulated on fresh inputs. The main continuation has its own unrevealed randomness. Treating concrete SHA-512 as the transcript random oracle is a modeling assumption. The receipt term must cover a second valid *encoding* for a previously signed body because full receipt bytes enter the challenge hashes. Exact matching against trusted issuer records or strong signature unforgeability under the accepted encodings suffices. The current CLI checks signatures and can pin the expected start. The current issuer records the first finish, while the standalone validator does not consult that ledger. A leaderboard identifying a specific attempt should supply the expected start. [Receipt issuance and validation](receipt.c) · [Verifier entry point](protocol.c)

For several admitted attempts, sum the per-attempt bounds or explicitly model how the entrant selects the target. For up to $s$ submissions under one receipt, replace $J+1$ by $J+s$ in both the field and rank bounds. Use the probability of any acceptance at the checkpoint and a fixed rule, such as taking the first accepted proof in each simulation, to select an opening. Count the range draw once. The timestamp authenticates when the issuer received the digest. Rewindable extractability gives a mathematical meaning to committing to a solution at that point. It cannot attest when particular arithmetic operations ran, whether a physical file already existed, or when the final proof was delivered. The July fixture also uses a fixed public problem for repeatability. [Timing rules](REFERENCE.md#challenge-and-timed-commitment)

## Implication for the benchmark

At $128^3$, $L=21$. Giving the prover $6.5\times10^{12}$ adaptive transcript queries makes the **whole field term** less than $7.7\times10^{-62}$. The ideal range term is about $2.94\times10^{-39}$ per independent stamp. These are two components of the bound. The stamped opening, mask expansion, and receipt assumptions have their own costs. A one-second VDF at every mutable challenge point would add about 43 seconds of serial evaluation to an honest proof, which took 3.821 seconds in the measured profile. The analysis supports leaving that delay out. A tight concrete end-to-end security rating for the deployed primitives still needs independent cryptographic review and concrete estimates for the reductions. [Measured prover time](benchmarks/SIGNED3D.md)
