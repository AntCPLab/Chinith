# sm4th-em-d2-128f-loose - Optimized Implementation

Optimized implementation of **sm4th-em-d2-128f-loose** with x86-oriented acceleration.

Protocol parameters follow `SM4th-EM-d2-128f-loose`:
`lambda=128`, `lambda_f=128`, `lambda_iv=128`, `ell=1024`, `tau=16`,
`w_grind=8`, `T_open=112`, `B=16`, `d=2`. The loose variant keeps SM4 as
the PRG, uses a 128-bit IV, and its EM-d2 leaf PRG path emits 162 bytes.

## Directory Structure

```
.
├── KAT_SIG.c                              # KAT vector generator entry
├── Makefile                               # Build rules (x86/non-x86 defaults)
├── README.md                              # This document
├── auxfunc.c / auxfunc.h                  # API Hash/XOF helper interface
├── bavc.c / bavc.h                        # BAVC commit/reconstruct
├── bench_cycles.h                         # Cycle-counter and stats helpers
├── compat.c / compat.h                    # Compatibility wrappers
├── drng.c / drng.h                        # Deterministic RNG used by KAT/bench
├── endian_compat.h                        # Endian helpers/macros
├── fallbacks.h                            # Feature fallback defines
├── fields.c / fields.h                    # GF arithmetic (with optional PCLMUL)
├── macros.h                               # Shared macros
├── owf.c / owf.h                          # One-way function helpers
├── params.c / params.h                    # Parameter set definitions
├── prg.c / prg.h                          # PRG interface/implementation
├── random_oracle.c / random_oracle.h      # RO / transcript hashing helpers
├── run_kat_sig.sh                         # KAT runner script
├── sig_impl.c / sig_impl.h                # Core sign/verify implementation
├── sig_impl_internal.h                    # Internal sig implementation types
├── sig_timing.c / sig_timing.h            # Optional sign/verify component timing
├── sm4_witness.c                          # Witness expansion for SM4
├── sm4th_em_d2_128f_loose.c / sm4th_em_d2_128f_loose.h   # Public API wrapper
├── sm4th_em_d2_128f_loose_AlgorithmInstance.c / .h # Algorithm instance entry points
├── sm4th_em_d2_128f_loose_bench.c                  # Benchmark entry
├── sm4th_sm4_128.c / sm4th_sm4_128.h      # SM4TH-specific SM4 wrapper
├── universal_hashing.c / .h               # VOLE universal hashing
├── utils.c / utils.h                      # Common utility helpers
├── utils_sm4/                             # SM4 components
│   ├── sm4.h                              # SM4 shared declarations
│   ├── sm4_affine.c                       # Affine transforms
│   ├── sm4_asm.S                          # x86 assembly SM4 backend
│   ├── sm4_core.c                         # SM4 core rounds
│   ├── sm4_ecb.c                          # ECB backend wrapper
│   ├── sm4_sbox.c                         # S-box tables/logic
│   └── sm4ni/                             # Imported SM4NI reference sources
│       ├── README.md
│       ├── sm4_ref.c / sm4_ref.h
│       └── sm4ni.c
├── vole.c / vole.h                        # VOLE protocol logic
└── x86_caps.h                             # x86 feature detection helpers
```

## Requirements

- GCC >= 7
- GNU Make
- C11 runtime (`-lm`)

Native Intel SM4 kernels require GCC 14 or newer, or Clang with
`sm4intrin.h`. Other compiler builds use the remaining supported paths.

## Build

Default build is release:

```bash
make sm4th_em_d2_128f_loose_bench
```

`make` and `make REF_USE_LOOKUP_TABLES=0` select the default table-free
cipher/proof helpers. `make REF_USE_LOOKUP_TABLES=1` explicitly enables the
legacy lookup-table path.

Build options:

| Variable | Default | Description |
|----------|---------|-------------|
| `NDEBUG` | `1` | `1`: release (`-O3 -DNDEBUG` with LTO), `0`: base `-O3` flags with assertions |
| `REF_USE_LOOKUP_TABLES` | `0` | `0`: table-free cipher/proof helpers; `1`: legacy lookup-table path |
| `FIELD_PCLMUL` | `1` on x86-64, `0` otherwise | Enable optional GF(2^128) carryless-multiply kernels, selected at runtime |
| `PRG_ACCE` | `1` on x86, `0` otherwise | Enable optional AES-NI/SSSE3 SM4NI simulation for the SM4 PRG |
| `INTEL_SM4_ACCE` | `1` on x86-64, `0` otherwise | Compile native Intel SM4 kernels when supported by the compiler |
| `COMPONENT_TIMING` | `0` | `1` prints sign/verify component timing |
| `COMPONENT_TIMING_VERBOSE` | `0` | `1` prints every measured timing span |

SM4 dispatch checks CPU and OS support at runtime and selects native Intel
SM4, AES-NI/SSSE3 SM4NI simulation, or portable C, in that order when the
corresponding kernels are enabled. Native SM4 is independent of `PRG_ACCE`
and `SM4_OWF_ACCE`; use `INTEL_SM4_ACCE=0` to disable it.
The release build uses `-mtune=native` when the compiler accepts it.

## Run

Benchmark:

```bash
./sm4th_em_d2_128f_loose_bench
./sm4th_em_d2_128f_loose_bench 100 0
./sm4th_em_d2_128f_loose_bench 100 8
./sm4th_em_d2_128f_loose_bench 100 0 --all
```

`ITERATIONS` defaults to `100` and is the actual number of KeyGen/Sign/Verify
combinations. There is no built-in warmup. The optional `MESSAGE_STEP` defaults
to `0`; message lengths are `56 + MESSAGE_STEP*i` bytes. Messages are
deterministic ASCII strings beginning with
`Chinith sm4th ublockith vistrutith 56-byte bench msg v1.`.

The default table has `operation`, `mean ms/op`, `mean cycles/op` and
`mean Mcycles/op` columns for KeyGen, Sign and Verify, followed by public-key,
secret-key and signature sizes in bytes. Milliseconds use `clock()` process
user-plus-system CPU time; cycles are user-mode hardware CPU cycles, not TSC
ticks or a frequency conversion. Mcycles are cycles divided by 1,000,000.
Unavailable cycle measurements show `N/A` and a reason.

`--all` runs speed measurement in a fresh process. On Linux, it then starts
a separate fresh process for memory measurement. Speed uses the requested
`ITERATIONS`; memory
includes all three complete API combinations. It also reports key/signature
sizes and the maximum child-process RSS observed at initial and syscall stops.
This includes initialization and all memory iterations and excludes the
observer. It is process memory, not a separate peak for each API. Memory-run
timings are discarded. RSS observation requires Linux; on macOS `--all`
completes successfully after speed measurement and reports `N/A` for RSS.

KAT:

```bash
bash run_kat_sig.sh
```

KAT output is written to `output/KAT_SIG_sm4th_em_d2_128f_loose.txt`.
To generate KATs with an explicit lookup mode, build and run the target directly:

```bash
make NDEBUG=1 REF_USE_LOOKUP_TABLES=1 KAT_SIG
./KAT_SIG
```

From the repository root, compare Optimized/Reference/Test_Vectors hashes with:

```bash
bash Chinith/Implementations/check_kat_hash.sh --variant sm4th_em_d2_128f_loose
```
