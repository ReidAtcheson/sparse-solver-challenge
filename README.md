# Sparse Solver Challenge

Solve a public, seeded sparse system $Ax=b$ using any solver. Commit to your solution, get a timestamp on the commitment, and generate a non-interactive proof. Someone else can check your numerical result on their own machine from the proof and public challenge inputs. Your full solution stays with you.

This repository contains the C reference prover and validator. There is currently no official submission endpoint or leaderboard. Keep a passing transcript for bragging rights, share a replay command, or agree on a challenge and clock with another team.

## Give this to a solver agent

> Use my solver on the registered signed 3D challenge in https://github.com/ReidAtcheson/sparse-solver-challenge. Build the reference tool and replay its archived proof first. Start a fresh 32³ practice round. Feed the seeded matrix and RHS to my solver, commit its solution, obtain a receipt, and generate a proof. Replay the proof in a directory containing only the public bundle. Report the validator exit status, backward error, commitment time, receipt mode, and paths to the three public files. Label a run using your own issuer as self-timed.

## Build and verify a result

On little-endian Linux, build with GNU Make, a C compiler supporting 128-bit integers, OpenSSL development headers and libsodium. On Debian or Ubuntu the build packages are `build-essential pkg-config libssl-dev libsodium-dev`. The default test suite also needs Python 3 and the OpenSSL command-line tool.

```sh
git clone https://github.com/ReidAtcheson/sparse-solver-challenge.git
cd sparse-solver-challenge
make
fixture=benchmarks/signed3d-public/grid-32-trial-01
./stencil verify "$fixture/authority.pub" "$fixture/proof.bin" "$fixture/start.receipt"
```

That archived run has 32,768 unknowns and a 16,716-byte proof. Look for `target=pass` and `backward_2=1.7474050162894104e-17`. The validator regenerates the matrix and right-hand side from the authenticated start. Run `make check` to exercise the local round trip, altered submissions and known-answer vectors.

## Play a round

The example uses the signed, indefinite $32^3$ profile. The accuracy target is joint 2-norm backward error at most $2^{-53}$ for the fixed-point vector actually committed. The validator checks the threshold with integer arithmetic. A faster time counts once the proof establishes a passing score.

Run these commands in one shell from the repository root. This practice round creates its own receipt issuer.

```sh
set -eu
tool="$PWD/stencil"
run=$(mktemp -d)
mkdir "$run/issuer" "$run/private" "$run/public"
cd "$run"

"$tool" keygen issuer/secret public/authority.pub
"$tool" startsigned3d issuer/secret 32 team-a public/start.receipt

# Replace this command with your solver when making your own attempt.
"$tool" solve public/authority.pub public/start.receipt private/x.f64

"$tool" commit public/authority.pub public/start.receipt private/x.f64 private/rows private/digest
"$tool" stamp issuer/secret public/start.receipt private/digest private/finish
"$tool" prove public/authority.pub public/start.receipt private/finish private/x.f64 private/rows public/proof.bin

(cd public && "$tool" verify authority.pub proof.bin start.receipt)
printf 'Replay bundle: %s/public\n' "$run"
```

**Use your own solver.** Open the signed start with `stencil_instance_open` and request matrix rows and RHS entries with `stencil_rows`. Write `private/x.f64` as exactly one little-endian binary64 per unknown in original index order, without a header. The same `commit`, `prove` and `verify` commands then work. You can also commit a contiguous in-memory solution through `libstencil.so`. A working Python example solves the July tridiagonal fixture with generated rows and hands a private memory descriptor to the proof worker. [C API](stencil.h) · [Python example](examples/library_solve.py)

**Read the result.** `rho` is the exact integer squared residual in the profile's units. On the signed 3D profile, `backward_2` measures $\|Ax-b\|_2/(\|A\|_2\|x\|_2+\|b\|_2)$. The validator returns **0** for a verified pass, **3** for a verified score that missed the target, **1** for rejection or an operational error, and **2** for incorrect command syntax. The `elapsed_ns` field runs from challenge start to receipt of the **commitment digest**. Proof generation can finish later. [Score definitions and supported profiles](REFERENCE.md)

## Share a replayable claim

Share the three files from `public/` for a local-receipt attempt. A reader with this tool can run the following inside that directory.

```sh
/path/to/stencil verify authority.pub proof.bin start.receipt
```

For a reproducible write-up, include the repository commit, solver and hardware, the verifier's output, and the receipt mode. An entrant operating its own issuer controls the clock and receipt randomness. Label those runs **self-timed**. Independent replay checks the proof against the supplied challenge and key. Trust in the timestamp and fresh randomness depends on who operated that issuer. For an independently timed local match, use a separate issuer that receives your digest, and have the players pin its public key and expected signed start through an independent channel.

For a common public start, the external receipt mode uses a preregistered drand Quicknet round to seed everyone's system, RFC 3161 to timestamp the committed digest, and a second fixed drand round to supply proof randomness. An organizer records the first eligible digest for each attempt. To replay it offline, the verifier needs the transcript plus the organizer's registration, TSA trust settings and winning digest. Anyone can organize a match. [External match and verification commands](BEACON.md)

**Use a public timestamp authority.** The external match supports FreeTSA and Sigstore Public Good. After a commitment, run `./examples/public-tsa sigstore stamp-commit reg start digest stamp.tsr`. Anyone with the registered public inputs can check it offline with `./examples/public-tsa sigstore verify-commit reg start digest stamp.tsr`. The guide includes live-issued stamps from both providers, an independent OpenSSL check, and a complete Quicknet/Sigstore attempt for offline replay. [Public timestamp authorities](PUBLIC_TIMESTAMPS.md)

## Protocol and generators

The reference verifies registered challenge families. These include seeded 2D and 3D diffusion, the signed 3D torus above, and a fixed July tridiagonal comparison. The experimental signed three-band generator is available for solver and ordering experiments. It still needs a registered RHS and scoring specification to support benchmark proofs. [Three-band generator](THREE_BAND.md)

Independent provers can target the published transcript format and test against known answers. The protocol is a research implementation with documented soundness and trust assumptions. [Prover](PROVER.md) · [Validator](VALIDATOR.md) · [Wire format and test vectors](INTEROP.md) · [Soundness analysis](SOUNDNESS.md)

## License

The original code and documentation are MIT licensed. The NumPy-compatible sampler carries its upstream notices. [MIT license](LICENSE) · [Third-party notices](LICENSE.numpy-three-band)
