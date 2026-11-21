# A timestamped proof of an exact linear-system residual

`stencil` takes a private binary64 solution file and public generator seed, commits to the fixed-point solution, and proves the exact integer squared residual. The timestamp authority can close the timed interval as soon as it receives the 32-byte commitment digest. The local verifier uses a pinned Ed25519 key and the expected start. The external receipt mode verifies two drand rounds and an RFC 3161 commitment timestamp against the judge’s registration, TSA trust settings and first accepted digest. [External receipt workflow](BEACON.md)

The current challenge uses the bounded signed three-band generator. The following implementation notes also cover historical test fixtures. [Challenge guide](README.md) · [Bounded generator specification](THREE_BAND.md)

The two original generators produce seeded random screened diffusion problems on square and cubic grids. Both operators are $4I$ plus a weighted Laplacian with zero Dirichlet boundary values. Each face has a conductance in $\{1,2,3,4\}$ shared by its adjacent cells. A separate seed-derived key generates the $\pm1$ RHS. The matrix-free CG solver regenerates rows and performs one iterative refinement. A separate 3D solver uses Intel MKL PARDISO to factor the matrix and refine the solution. The proof uses the generator's row iterator. A public generator can emit terms in arbitrary column order, revisit columns, and have a different sparsity pattern in every row. For these diffusion fixtures, validator time scales with the number of generated entries and rows, and its memory scales with the square root of the number of rows.

The signed-unit 3D profile adds a shared-exponent 80-bit solution and certifies joint 2-norm backward error down to a threshold of $2^{-53}$. Its matrix has seven unit-magnitude entries per row, and its RHS has 1-norm one. [How the proof components fit together](CONTRACTS.md) · [Protocol](#shared-exponent-signed-3d-profile) · [Measured size, time and memory](benchmarks/SIGNED3D.md)

The default signed three-band challenge produces matrices with a seed-dependent graph and independently reusable sign draws. It is available as a UNIX command, C library, and NumPy reference. [Generator, sparse output and replay rules](THREE_BAND.md) · [Challenge-specific scoring and verifier costs](THREE_BAND_PROOF.md)

## Using the reference from another solver

`make` builds both the UNIX tool and `libstencil.so`. Open an authenticated start with `stencil_instance_open`, request any contiguous range of matrix rows and RHS entries with `stencil_rows`, and pass the solver’s contiguous binary64 buffer to `stencil_commit`. The caller chooses its batch size and owns the resulting CSR arrays. The library returns the same row cache and 32-byte digest as the CLI. [C API](stencil.h)

The Linux Python example reads bounded three-band rows in physical units, solves with SciPy sparse LU, and commits a solution in an anonymous memory mapping. It passes the descriptor to a separate C proof worker. The example requires NumPy and SciPy. It runs the validator with public inputs after the private mapping has closed. Run `python3 examples/library_solve.py demo-public` in the built source tree, using a fresh output directory. The algebraic prover uses temporary scratch for its folds. [Python example](examples/library_solve.py)

Independent implementations can use any solver and generate the proof themselves. Compare encodings and challenges against the public known-answer transcript, then run the reference validator on the resulting proof. The signed start binds the generator and scoring rules to their versioned profile. [Protocol and interoperability vectors](INTEROP.md) · [External transcript format](BEACON.md)

## Build and run

The optional default numerical solver builds when pkg-config finds SuperLU (Debian or Ubuntu package `libsuperlu-dev`). The implementation uses little-endian binary64, a C compiler with 128-bit integer support, 64-bit POSIX file offsets, OpenSSL libcrypto and libsodium. The Makefile uses pkg-config for libsodium where available and otherwise links the installed Linux libsodium.so.23 ABI. Set `SODIUM_LIBS=-lsodium` for a conventional development installation. Python 3 is used for independent tests and measurement orchestration. The protocol, signer, solver, prover, and verifier are C.

```sh
make
make check
mkdir -p run/authority run/solver run/validator
tool=$PWD/stencil
cd run
"$tool" keygen authority/key authority/pub
"$tool" start authority/key 1024 team-a start
"$tool" solve authority/pub start solver/x.f64
"$tool" commit authority/pub start solver/x.f64 solver/rows solver/digest

# Binary request to the issuer. In deployment these are separate machines.
cat start solver/digest | "$tool" stamp-stdio authority/key team-a > finish

"$tool" prove authority/pub start finish solver/x.f64 solver/rows solver/proof.bin
cp solver/proof.bin validator/
(cd validator && "$tool" verify ../authority/pub proof.bin ../start)
```

For a cube, use `fixture start3d` and the stand-alone direct solver. Building `direct3d` requires MKL development headers and the `mkl_rt` and GNU threading libraries. On Ubuntu 24.04 the VM setup installs `libmkl-dev` and `libmkl-gnu-thread`. Set `MKL_CPPFLAGS` or `MKL_LIBS` when building against an installation in a nonstandard location. The proof and validator use the same dependencies across generator profiles.

```sh
# From the source directory, following the example above.
make direct3d
./stencil fixture start3d run/authority/key 64 team-a run/start3d
MKL_NUM_THREADS=8 OMP_NUM_THREADS=8 MKL_DYNAMIC=FALSE \
  ./stencil-direct3d run/authority/pub run/start3d run/solver/x3d.f64
./stencil commit run/authority/pub run/start3d run/solver/x3d.f64 run/solver/rows3d run/solver/digest3d
./stencil stamp run/authority/key run/start3d run/solver/digest3d run/finish3d
./stencil prove run/authority/pub run/start3d run/finish3d run/solver/x3d.f64 run/solver/rows3d run/solver/proof3d.bin
cp run/solver/proof3d.bin run/validator/
./stencil verify run/authority/pub run/validator/proof3d.bin run/start3d
```

The direct solver assembles the upper triangle of the seven-point SPD stencil in CSR with sorted column indices, uses PARDISO’s 64-bit index interface and nested dissection, and applies one correction with the same factor. The output has one binary64 value per physical cell in the order $i=x+d(y+dz)$ for cube side $d$. For the five-point square the order is $i=x+dy$.

An external solver can supply `x.f64` directly. It holds exactly one little-endian IEEE binary64 per unknown in row order, with no header. The file is seekable and stays at the prover. For the two original diffusion profiles the prover scales each value by $2^{58}$, rounds to the nearest integer with ties to even, and requires a signed 64-bit result. Input magnitudes therefore extend to −32 on the negative side and to the largest binary64 below 32 on the positive side. The certified vector is the resulting fixed-point vector. The receipt binds that vector even when multiple binary64 files round to it.

The file-based authority command `stencil stamp SECRET START DIGEST FINISH` uses the same ledger as `stamp-stdio`. For the stream endpoint, configure the authenticated transport to supply the registered entry label, for example as a fixed argument in an SSH forced command. The request is exactly the 192-byte start followed by the 32-byte digest and EOF. On success stdout carries the 160-byte signed finish receipt. The solver keeps both the row cache and the solution. Pin its 32-byte Ed25519 public key through an independent channel.

A successful validator prints the decimal integer score, relative RHS error, threshold decision, elapsed nanoseconds, and attempt ID. Exit status 0 means a certified passing score, 3 means a certified score above the numerical target, 1 means rejection or an operational error, and 2 indicates incorrect command syntax. Omit the optional expected start only when accepting any registered attempt from the pinned authority.

## Challenge and timed commitment

1. The authority registers the public profile, grid side, and entrant label. Its first start for that registration binds its UTC timestamp and 32 fresh random bytes in a signed receipt. SHA-256 of a domain label and that signed receipt gives the 32-byte matrix and RHS seed. The authority returns identical bytes on a retry.
2. Let $n=d^2$ for a square or $n=d^3$ for a cube and set $L=\log_2 n$. Lay out the quantized vector as $h=n/w$ contiguous rows of width $w=2^{\lfloor L/2\rfloor}$. Physical index $iw+j$ goes in entry $(i,j)$ and all entries are used. A $128^3$ grid, for example, has $h=2048$ and $w=1024$. Public Ristretto255 points $G_j$ come from SHA-512 of a domain label and the column number, followed by the Ristretto element-derivation map. Commit each row as $C_i=\sum_j X_{ij}G_j$. The timestamp digest hashes a domain label, the table shape, and all ordered canonical row encodings using SHA-256. Square tables encode the width once, preserving the original 2D format. Rectangular tables have a distinct domain label and encode the width followed by the height. The row cache has $32h$ bytes and stays local until proof assembly.
3. On first receipt of the digest, the authority signs its time, the registered start's attempt ID, the digest, and 16 fresh random bytes. It durably records the winner before returning the receipt. An identical retry recovers the same finish, including its entropy. A conflicting digest fails. The score clock stops here. The verifier recognizes that score once the later proof validates against the stamped digest.
4. The signed elapsed time is the difference of the authority's two timestamps. It includes local commitment work, launch overhead, and delivery to the authority. Deployment clock accuracy and release/transport latency determine how to interpret close finishes. The local benchmark uses a test signing key and the host clock. For independently attested leaderboard time, operate the signer separately, authenticate enrollment, keep its key at one fixed protected path, and retain the registration and finish ledgers alongside the key. POSIX atomic hard links and file and directory fsync preserve first issuance. A rolled-back ledger loses that guarantee.

The row commitment is the main cost before stamping. Timestamping a plain hash of the input file would require a separate proof linking that hash computation to the vector opened later.

## Original diffusion proof

Let $S=2^{58}$, $R_i=\sum_j A_{ij}X_j-Sb_i$, and use the Ristretto scalar field of order $q=2^{252}+27742317777372353535851937790883648493$. A tilde denotes the multilinear extension on the Boolean cube. Index bit zero is folded first. Write $e_u(i)=\prod_k (i_k u_k + (1-i_k)(1-u_k))$.

**Range.** After the digest is fixed, the signed receipt prefix seeds ChaCha20 to select 128 random subsets of the full vector. The transcript gives their signed integer sums $t_k$, with $|t_k|\le T=n2^{63}$. For a fixed field vector with a coordinate of centered magnitude greater than $2T$, condition on every other bit of a subset. Toggling the remaining bit separates the two possible sums by centered distance greater than $2T$. At most one can lift into $[-T,T]$. The 128 independent ideal subset tests thus accept such a fixed vector with probability at most $2^{-128}$. The implementation expands its seed pseudorandomly. No range argument for the residual is needed in this field and profile.

**Norm.** The first degree-two sumcheck starts from the claimed $\rho=\sum_i R_i^2$. It ends at the verifier's check against $\widetilde R(u)^2$. The transcript gives $\widetilde R(u)$ explicitly.

**Matvec and ranges.** Hash the prefix through that residual endpoint to obtain 128 batching coefficients $c_k$. Let $m_k(j)$ be the subset bits. The second degree-two sumcheck starts from

$$
\widetilde R(u)+S\widetilde b(u)+\sum_k c_k t_k
=\sum_j X_j\left(\sum_i e_u(i)A_{ij}+\sum_k c_k m_k(j)\right).
$$

It ends at $\widetilde X(v)$ times the public weight evaluated at $v$. The validator scans the generated rows once to accumulate $\sum_{ij}e_u(i) A_{ij}e_v(j)$, $\widetilde b(u)$, and the exact $\sum_i b_i^2$. It also streams the public mask bits for their batched endpoint. It stores two length-$w$ and two length-$h$ equality-weight arrays and a bounded column cache. Arbitrary nonlocal sparsity costs more cache misses at the prover. It computes these endpoints directly from its public inputs.

**Opening.** Write $v=(v_{\rm low},v_{\rm high})$. The prover reveals one width-$w$ row with entries $z_j=\sum_{i=0}^{h-1}e_{v_{\rm high}}(i)X_{ij}$. The low point uses $\log_2 w$ coordinates and the high point uses $\log_2 h$. The verifier checks both the stamped digest and

$$
\sum_i e_{v_{\rm high}}(i)C_i=\sum_j z_jG_j,
\qquad
\widetilde X(v)=\sum_j e_{v_{\rm low}}(j)z_j .
$$

The proof contains row commitments, 128 subset sums and a folded row. It gives partial information about the witness. Applications requiring zero knowledge need a different opening and range design. The square-root row arrangement follows the construction in the Hyrax paper. The opening used here reveals the folded row directly. [Wahby et al.](https://cs.nyu.edu/~mwalfish/papers/hyrax-oakland18.pdf) · [Ristretto255 specification](https://www.rfc-editor.org/rfc/rfc9496.html)

**Integer lifting.** The signed profiles accept power-of-two physical sides from 512 through 32,768 for a square and from 32 through 1,024 for a cube. Both ranges give $n\le2^{30}$. Under the range argument the centered solution entries have magnitude at most $2n2^{63}\le2^{94}$. The generic integer profile permits an emitted absolute row sum up to $2^{16}$ and signed 32-bit RHS values. Every integer residual magnitude is at most $2^{110}+2^{89}<2^{111}$. Consequently $\sum R_i^2<2^{252}<q$, and the canonical field result is the ordinary integer energy. For these diffusion fixtures the actual absolute row sum is at most 36 in 2D and 52 in 3D, and $|b_i|=1$.

The exact pass criterion for relative RHS error at most $2^{-50}$ is $\rho\le2^{16}\sum_i b_i^2$. The reported floating approximation is $\sqrt{\rho/\sum_i b_i^2}/S$. For zero RHS, the target requires zero energy. The public proof establishes the loose bound needed for integer lifting. Signed 64-bit is the honest input format, and floating-point provenance is outside the certified statement.

## Transcript and soundness assumptions

For the original format and $L=\log_2 n$, the transcript contains the following consecutive fields. Integers and scalars use little-endian encoding. Scalar decoders require values below $q$.

| Field | Bytes |
|---|---:|
| Format magic, signed start, signed finish | 8 + 192 + 160 |
| Ordered canonical row commitments | $32h$ |
| Canonical integer energy | 32 |
| Signed two's-complement subset sums | $128\times16$ |
| Norm sumcheck rounds | $64L$ |
| Residual endpoint | 32 |
| Batched matvec sumcheck rounds | $64L$ |
| Canonical folded-row scalars | $32w$ |
| **Total** | **$32(h+w) + 128L + 2472$** |

Each round sends $g(0)$ and the coefficient of $t^2$. The current claim determines $g(1)$ since $g(0)+g(1)$ equals that claim. SHA-512 absorbs every transmitted field in order. A challenge copies the hash state, appends its role byte and LE32 round index, then reduces the 64-byte digest modulo $q$. The mask seed uses the first 32 digest bytes at the prefix ending with the finish receipt. The other domain labels, mask layout and signed receipt offsets are specified in the corresponding C modules. Trailing bytes, invalid group encodings, noncanonical scalars, invalid signatures and mismatched public starts are rejected.

The range estimate applies to a vector fixed before the finish entropy. In the ideal interactive analysis, two degree-two sumchecks contribute at most $4L/q$, with another $1/q$ for batching, conditional on a bound vector and sound opening. For the shared-exponent format, a classical random-oracle argument covers adaptive Fiat–Shamir queries and recovers a row opening by rewinding a sufficiently successful prover at the stamp request. Its assumptions include fresh authenticated receipts, collision resistance of the row digest, pseudorandom mask expansion, and hardness of finding a relation among the hash-derived generators. The cost of extraction enters the security reduction. A tight deployed security rating and independent cryptographic review remain open. The optimized prover's group arithmetic is variable-time. The verifier uses libsodium group operations. [Soundness analysis](SOUNDNESS.md) · [Hyrax](https://eprint.iacr.org/2017/1132) · [Ristretto255](https://www.rfc-editor.org/rfc/rfc9496.html)

## Shared-exponent signed 3D profile

Run the following commands with a new output directory. The proof contains the receipts. The authority key and independently received start are the validator's public trust inputs.

```sh
mkdir signed-run
cd signed-run
tool=../stencil
"$tool" keygen sk pk
"$tool" fixture startsigned3d sk 64 entrant start
"$tool" solve pk start x.f64
"$tool" commit pk start x.f64 rows digest
"$tool" stamp sk start digest finish
"$tool" prove pk start finish x.f64 rows proof.bin
"$tool" verify pk proof.bin start
```

**Matrix and RHS.** The profile ID is `signed-unit-torus-3d-backward80-v2`. Write $m=d^3$ for the number of unknowns. The generator constructs a periodic 3D cube with adjacency matrix $G$, then emits $A=D(I+G)D$. The diagonal entries of $D$ are seed-derived signs. The diagonal of $A$ is $+1$, and the six neighbor coefficients are products of their two vertex signs. These edge signs are correlated. An independently keyed sequence gives $b_i=\sigma_i/m$ with $\sigma_i\in\{-1,1\}$ exactly. The generator needs constant working memory.

The sign change preserves the spectrum of $I+G$. The unsigned constant mode attains eigenvalue 7 and the alternating mode attains $-5$, so $A$ is indefinite and $\|A\|_1=\|A\|_2=7$. The eigenvalues are $1+2\sum_{j=1}^3\cos(2\pi k_j/d)$. An integer-interval check certifies that the minimum absolute eigenvalue is positive and $\|A^{-1}\|_1\le\sqrt m/\min|\lambda|<10^{16}$ at every registered side (powers of two from 32 through 1024). Reproduce the bound with `python3 tests/signed_spectrum.py`. The built-in solver uses a 3D FFT on the unsigned matrix and one residual correction. The proof checks the generated rows independently of the solver.

**Encoding and score.** For nonzero binary64 input $y$, set $E=\lceil\log_2\max_j |y_j|\rceil$. Use $E=0$ for the zero vector. The prover rounds $X_j=y_j2^{78-E}$ to nearest with ties to even and certifies $x=2^{E-78}X$. The honest encoding has $|X_j|\le 2^{78}$. For $m\le2^{30}$, rounding perturbs a nonzero input by at most $2^{-63}\|y\|_2$ in 2-norm. The admitted exponent interval is $[-\log_2 m-30,54]$. It covers the stated solution range and provides a finite lifting budget. The signed LE32 exponent is stored first in the row cache and included in the domain-separated timestamp digest.

Let $s=78-E-\log_2 m$, $k=2^{\max(-s,0)}$, $h=2^{\max(s,0)}$. The proof authenticates two integers, $\rho=\|kAX-h\sigma\|_2^2$ and $Q=\|X\|_2^2$. The verifier prints both integers and both scores below.

$$
\mathrm{relative\_rhs}=\frac{\sqrt\rho}{h\sqrt m},\qquad
\mathrm{backward\_2}=\frac{\sqrt\rho}{7k\sqrt Q+h\sqrt m}.
$$

The pass criterion is $\mathrm{backward\_2}\le2^{-53}$. The validator checks it with integer arithmetic, including equality. Set $a=49k^2Q$, $b=h^2m$ and $t=2^{106}\rho-a-b$. Accept if $t\le0$ or $t^2\le4ab$. Floating-point square roots are used only for display.

**Proof and lifting.** The residual sumcheck runs on $R=kAX-h\sigma$. The prover sends $Q$ before the verifier derives the independent batching coefficient $\lambda$. In the matvec sumcheck it adds $\lambda Q$ to the claim and $\lambda X_j$ to the weight multiplied by $X_j$. At the endpoint the verifier uses the same authenticated $\widetilde X(v)$ for both factors. Both sumchecks remain degree two and one opening suffices.

The 128 subset tests now use $T=m2^{78}$. Subject to the range and commitment soundness assumptions above, $|X_j|\le 2T\le2^{109}$ for the centered lift, so its squared energy is at most $2^{248}<q$. The validator can therefore apply the honest upper bound $Q\le m2^{156}$ to the integer energy. With $k\le64$, $h\le2^{108}$ and $\|A\|_2=7$, the ordinary residual satisfies $\|R\|_2\le 7k\sqrt Q+h\sqrt m < 2^{124}$. Its squared energy also fits below $q$. These checks give integer meaning even to a certified numerical miss. The signed 80-bit limit describes the honest encoding. The proof authenticates the energy and a looser coordinate bound.

**Transcript size.** Version 2 uses magic `STNPRF02`, inserts the four-byte signed exponent immediately after the finish receipt, and inserts the 32-byte canonical $Q$ immediately after $\rho$. The subset sums and opening keep their original widths. With $L=\log_2 m$, commitment width $w$ and height $v=m/w$, the complete proof is $32(v+w)+128L+2508$ bytes, exactly 36 bytes larger than version 1 at the same row count.

## Working memory and generator contract

The private input occupies $8n$ bytes. The prover reads and quantizes it in bounded chunks and keeps at most one large private scratch file of $32n$ bytes. The residual sumcheck folds that file in place and closes it. The matvec then uses a fresh file of the same maximum size for the weighted transpose. Two weights are replaced in place by one pair of folded field values. Later rounds truncate the file geometrically. Scratch files are private and unlinked. Use `TMPDIR` on a disk-backed filesystem when enforcing a RAM budget. On tmpfs the scratch space itself consumes memory.

For the fixed-stencil fixtures in this comparison, the process working set is $O(\sqrt n)$ for commitment, proving, and validation. The row generator has $O(1)$ working state. The input, benchmark artifacts, and OS filesystem cache are accounted separately from process RSS. The original commit stage scans the binary64 file once with bounded row buffers. The shared-exponent profile takes an initial scan to choose its exponent. The verifier uses only RAM for its working tables. The CG solver uses five binary64 vectors during refinement, or $40n$ bytes. The direct solver keeps CSR input, factor data, and numerical vectors during the solve. Its peak RSS includes factorization fill and MKL workspace. The ordering of memory use depends on the solver being compared and on the host's accounting of file cache.

The signed 2D profile ID is `seeded-stencil-exact-residual-v1` and the signed 3D ID is `seeded-stencil-3d-exact-residual-v1`. To add a generator, implement its seed setup in `matrix_init_profile` and its row stream in `matrix_visit`, then register a distinct profile ID with the receipt issuer and verifier. The callback emits integer terms and returns the RHS. The proof and validator request rows in ascending order within each matrix pass. A generator may regenerate rows on demand or keep a bounded sequential cursor and reset it at each pass. The proof does not materialize $A$. The time bounds assume generation overhead proportional to emitted work; a generator that restarts a long scan for every row can cost more. Integer-coefficient or agreed fixed-point encodings, row bounds and an exact score normalization are part of the profile. The included CG command is specific to the test stencil and optional for other generators.

## Reproduce measurements

**July tridiagonal comparison.** `fixture startblog SECRET ROWS ENTRY START` selects a fixed replay of the July matrix and RHS. It uses the original public nonce at every row count and issues fresh commitment receipts. The C prover and validator use the shared-exponent format. The harness checks every encoded coordinate against the original Rust solver. [Matched-process RSS and transcript measurements](benchmarks/blog-comparison/README.md)

**2D on Linux.**

```sh
make
python3 benchmarks/run.py --output benchmarks/results.json --public-dir benchmarks/public
./stencil verify benchmarks/public/authority.pub benchmarks/public/proof.bin benchmarks/public/start.receipt
```

The runner uses fresh registrations, signed random seeds, three trials per grid, and a separate process per stage. A Linux C sampler times fork-to-exit and reads each child's own peak RSS through wait4. A separate million-row run enforces a 32 MiB address-space ceiling and compares the deterministic proof bytes. The public directory holds the test authority’s public key, signed challenge, and transcript. A summary appears in [the measurements](benchmarks/RESULTS.md).


**3D on a Linux VM.** On a machine with the direct-solver dependencies installed, run the following commands from the source directory into a fresh results directory. The `--threads` option controls the solver. The prover and validator each run in their own single-threaded process.

```sh
make stencil direct3d
python3 benchmarks/run3d.py --sides 32 64 128 --trials 3 --threads 8 \
    --check-cap-mib 32 --output run-vm/results.json --public-dir run-vm/public
replay=run-vm/public/grid-128-trial-01
./stencil verify "$replay/authority.pub" "$replay/proof.bin" "$replay/start.receipt"
```

Each completed trial records elapsed time and peak RSS separately for the solver, commitment, stamp, prover and validator, along with the proof byte count and exact score. The runner regenerates the matrix in Python and checks the integer score for the first completed trial at each size. It deletes the private solution before invoking the verifier, which receives the transcript, pinned authority public key, and signed start. The optional address-space check repeats proving and validation under the specified process limit. Use a disk-backed directory for `--scratch-dir`.

The GCE wrapper in `benchmarks/vm3d.sh` accepts a project, zone, new instance name and new local results directory. It provisions the VM, runs the benchmark, copies the public artifacts back, and deletes the VM.


## Receipt providers

The local Ed25519 issuer supplies signed fixed-size receipts in transcript versions 1 and 2. Version 3 uses drand Quicknet for the start and post-commitment challenge, and RFC 3161 for the commitment time. Its verifier checks both round signatures, the timestamp response, and the judge’s independently pinned inputs. Transport uses ordinary HTTP tools outside the verification code. [Registration, commands, wire format and trust policy](BEACON.md)
