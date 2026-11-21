# Sparse Solver Challenge

Solve a public, seeded **bounded signed three-band** sparse system $Ax=b$ using any solver. Commit to your solution, get a timestamp on the commitment, and generate a non-interactive proof. Someone else can check your numerical result on their own machine from the proof and public challenge inputs. Your full solution stays with you.

This repository contains the C reference prover and validator. There is currently no official submission endpoint or leaderboard. Keep a passing transcript for bragging rights, share a replay command, or agree on a challenge and clock with another team.

## Give this to a solver agent

> Clone https://github.com/ReidAtcheson/sparse-solver-challenge, build the tool, and verify the archived proof. Start a fresh 4,096-row signed three-band round with `stencil start`. Feed the authenticated matrix and RHS to my solver, commit its solution, timestamp the digest, and generate a proof. Run the validator in a fresh directory containing only the public key, signed start and transcript. Return those three files, the validator exit status, `backward_2_upper`, proof size, and separate solve, prove and verify times and peak RSS. Label a run using your own issuer as self-timed.

## Build and verify a result

On Debian or Ubuntu, install `build-essential pkg-config libssl-dev libsodium-dev libsuperlu-dev`. The included numerical solver uses SuperLU. Entrants supplying their own solution and machines dedicated to validation can omit SuperLU. The reference targets little-endian Linux. The test suite also uses Python 3 and the OpenSSL command-line tool.

```sh
git clone https://github.com/ReidAtcheson/sparse-solver-challenge.git
cd sparse-solver-challenge
make
fixture=benchmarks/bounded-three-band/public
./stencil verify "$fixture/authority.pub" "$fixture/proof.bin" "$fixture/start.receipt"
```

Look for `target=pass` and the certified numerical score. The validator regenerates the signed matrix and RHS from the authenticated start. Run `make check` for regression and altered-proof tests. [End-to-end timings, peak RSS and proof sizes](benchmarks/bounded-three-band/README.md)

## Play a round

Each fresh seed draws a symmetric sparse matrix with $7n-12$ entries of magnitude one, including a signed diagonal. The three bands are centered at offsets $1$, $n^{1/3}$ and $n^{2/3}$. Each band reaches at most 200 columns on either side of its center. Where eligible, 1% of draws come from the 100–200-index tail. Positions and signs change with the seed. Each RHS entry is $+1/n$ or $-1/n$. The instance is issued as drawn, including a possible singular matrix. The registered row counts are powers of two from 1,024 through 65,536. [Generator and seed derivation](THREE_BAND.md)

Run these commands in one shell from the repository root. This practice round creates its own receipt issuer.

```sh
set -eu
tool="$PWD/stencil"
run=$(mktemp -d)
mkdir "$run/issuer" "$run/private" "$run/public"
cd "$run"

"$tool" keygen issuer/secret public/authority.pub
"$tool" start issuer/secret 4096 team-a public/start.receipt

# Replace this command with your solver when making your own attempt.
"$tool" solve public/authority.pub public/start.receipt private/x.f64

"$tool" commit public/authority.pub public/start.receipt private/x.f64 private/rows private/digest
"$tool" stamp issuer/secret public/start.receipt private/digest private/finish
"$tool" prove public/authority.pub public/start.receipt private/finish private/x.f64 private/rows public/proof.bin

(cd public && "$tool" verify authority.pub proof.bin start.receipt)
printf 'Replay bundle: %s/public\n' "$run"
```

**Use your own solver.** Open the signed start with `stencil_instance_open` and request matrix rows and RHS entries with `stencil_rows`. Write `private/x.f64` as exactly one little-endian binary64 per unknown in original index order, without a header. The same `commit`, `prove` and `verify` commands then work. You can also commit a contiguous in-memory solution through `libstencil.so`. The reference SuperLU solver performs fresh symbolic ordering, factorization and two refinement steps on each draw. The Python example shows how to solve the same challenge with SciPy and commit the in-memory vector. [C API](stencil.h) · [Python example](examples/library_solve.py) · [SuperLU solver](three_band_lu.c)

**Read the result.** `rho` is the exact integer squared residual in the profile's units. The validator computes a certified upper bound on joint 2-norm backward error for the committed fixed-point vector. It uses $L=\sqrt{(7n-12)/n}\leq\|A\|_2$ in the denominator. Passing requires `backward_2_upper` at most $2^{-53}$, checked with integers. The validator returns **0** for a verified pass, **3** for a verified score that missed the target, **1** for rejection or an operational error, and **2** for incorrect command syntax. The `elapsed_ns` field runs from challenge start to receipt of the **commitment digest**. Proof generation can finish later. [Exact score and integer bounds](THREE_BAND_PROOF.md)

## Share a replayable claim

Share the three files from `public/` for a local-receipt attempt. A reader with this tool can run the following inside that directory.

```sh
/path/to/stencil verify authority.pub proof.bin start.receipt
```

For a reproducible write-up, include the repository commit, solver and hardware, the verifier's output, and the receipt mode. An entrant operating its own issuer controls the clock and receipt randomness. Label those runs **self-timed**. Independent replay checks the proof against the supplied challenge and key. Trust in the timestamp and fresh randomness depends on who operated that issuer. For an independently timed local match, use a separate issuer that receives your digest, and have the players pin its public key and expected signed start through an independent channel.

For a common public start, the external receipt mode uses a preregistered drand Quicknet round to seed everyone's system, RFC 3161 to timestamp the committed digest, and a second fixed drand round to supply proof randomness. An organizer records the first eligible digest for each attempt. To replay it offline, the verifier needs the transcript plus the organizer's registration, TSA trust settings and winning digest. Anyone can organize a match. [External match and verification commands](BEACON.md)

**Use a public timestamp authority.** The external match supports FreeTSA and Sigstore Public Good. After a commitment, run `./examples/public-tsa sigstore stamp-commit reg start digest stamp.tsr`. Anyone with the registered public inputs can check it offline with `./examples/public-tsa sigstore verify-commit reg start digest stamp.tsr`. The guide includes live-issued stamps from both providers, an independent OpenSSL check, and a complete Quicknet/Sigstore attempt for offline replay. [Public timestamp authorities](PUBLIC_TIMESTAMPS.md)

## Protocol and matrix generator

New local and drand registrations issue a single matrix profile. Its authenticated ID is `signed-three-band-backward80-v2`. A public verifier streams the seeded edges and accumulates both symmetric contributions. Each draw examines at most 401 offsets. With at most three draws per row, regenerating the complete pattern takes linear work. [Three-band generator](THREE_BAND.md) · [Generation speed and ordering reuse](benchmarks/BOUNDED_PATTERN.md) · [Proof specification](THREE_BAND_PROOF.md)

Independent provers can target the published transcript format and test against known answers. The protocol is a research implementation with documented soundness and trust assumptions. [Prover](PROVER.md) · [Validator](VALIDATOR.md) · [Wire format and test vectors](INTEROP.md) · [Soundness analysis](SOUNDNESS.md)

## License

The original code and documentation are MIT licensed. The NumPy-compatible sampler carries its upstream notices. [MIT license](LICENSE) · [Third-party notices](LICENSE.numpy-three-band)
