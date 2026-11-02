# sm4th-d3-128s-tight - Optimized Implementation

Optimized implementation of **sm4th-d3-128s-tight** with x86-oriented
acceleration. This tight variant uses SM4 for the OWF and Ballet-256/256 as the
are intentionally not part of this target.

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
├── prg.c / prg.h                          # Ballet PRG interface/implementation
├── random_oracle.c / random_oracle.h      # RO / transcript hashing helpers
├── run_kat_sig.sh                         # KAT runner script
├── sig_impl.c / sig_impl.h                # Core sign/verify implementation
├── sig_impl_internal.h                    # Internal sig implementation types
├── sig_timing.c / sig_timing.h            # Optional sign/verify component timing
├── sm4_witness.c                          # Witness expansion for SM4
├── sm4th_d3_128s_tight.c / .h             # Public API wrapper
├── sm4th_d3_128s_tight_AlgorithmInstance.c / .h # Algorithm instance entry points
├── sm4th_d3_128s_tight_bench.c            # Benchmark entry
├── sm4th_sm4_128.c / sm4th_sm4_128.h      # SM4TH-specific SM4 wrapper
├── universal_hashing.c / .h               # VOLE universal hashing
├── utils.c / utils.h                      # Common utility helpers
├── utils_ballet/                          # Ballet-256/256 PRG components
│   ├── Ballet256256_coreE.c / .h          # Ballet encryption/key schedule
│   └── BalletDef.h                        # Ballet types/macros
├── utils_sm4/                             # SM4 OWF components
│   ├── sm4.h                              # SM4 shared declarations
│   ├── sm4_affine.c                       # Affine transforms
│   ├── sm4_asm.S                          # x86 assembly SM4 OWF backend
│   ├── sm4_core.c                         # SM4 core rounds
│   ├── sm4_ecb.c                          # ECB backend wrapper
│   └── sm4_sbox.c                         # S-box tables/logic
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
make sm4th_d3_128s_tight_bench
```

`make` and `make REF_USE_LOOKUP_TABLES=0` select the default table-free
cipher/proof helpers. `make REF_USE_LOOKUP_TABLES=1` explicitly enables the
legacy lookup-table path.

Build options:

| Variable | Default | Description |
|----------|---------|-------------|
| `NDEBUG` | `1` | `1`: release (`-O3 -DNDEBUG` with LTO), `0`: base `-O3` flags with assertions |
| `REF_USE_LOOKUP_TABLES` | `0` | `0`: table-free cipher/proof helpers; `1`: legacy lookup-table path |
| `FIELD_PCLMUL` | `1` on x86-64, `0` otherwise | Enable optional GF(2^160) carryless-multiply kernels, selected at runtime |
| `PRG_ACCE` | `1` on x86, `0` otherwise | Enable optional Ballet PRG AVX2 acceleration |
| `SM4_OWF_ACCE` | `1` on x86, `0` otherwise | Enable optional AES-NI SM4 simulation for the OWF |
| `INTEL_SM4_ACCE` | `1` on x86-64, `0` otherwise | Compile native Intel SM4 kernels when supported by the compiler |
| `COMPONENT_TIMING` | `0` | `1` prints sign/verify component timing |
| `COMPONENT_TIMING_VERBOSE` | `0` | `1` prints every measured timing span |

SM4 dispatch checks CPU and OS support at runtime and selects native Intel
SM4, AES-NI/SSSE3 SM4NI simulation, or portable C, in that order when the
corresponding kernels are enabled. Native SM4 is independent of `PRG_ACCE`
and `SM4_OWF_ACCE`; use `INTEL_SM4_ACCE=0` to disable it.
This tight variant keeps Ballet as its PRG; SM4 dispatch applies to the OWF.

To disable the optional PRG, SM4 OWF and field accelerators:

```bash
make clean
make NDEBUG=1 PRG_ACCE=0 SM4_OWF_ACCE=0 INTEL_SM4_ACCE=0 FIELD_PCLMUL=0 KAT_SIG sm4th_d3_128s_tight_bench
```

## Run

Benchmark:

```bash
./sm4th_d3_128s_tight_bench
./sm4th_d3_128s_tight_bench 100 0
./sm4th_d3_128s_tight_bench 100 8
./sm4th_d3_128s_tight_bench 100 0 --all
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

KAT output is written to `output/KAT_SIG_sm4th_d3_128s_tight.txt`.
To generate KATs with an explicit lookup mode, build and run the target directly:

```bash
make NDEBUG=1 REF_USE_LOOKUP_TABLES=1 KAT_SIG
./KAT_SIG
```

From the repository root, compare Optimized/Reference/Test_Vectors hashes with:

```bash
bash Chinith/Implementations/check_kat_hash.sh --variant sm4th_d3_128s_tight
```
