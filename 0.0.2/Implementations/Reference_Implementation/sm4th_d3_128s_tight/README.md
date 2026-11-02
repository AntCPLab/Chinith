# sm4th-d3-128s-tight - Reference Implementation

Portable C reference implementation of **sm4th-d3-128s-tight**. This directory
intentionally contains no instruction-set acceleration sources, backend probes,
or acceleration build flags. The tight variant uses SM4 for the OWF and the
portable Ballet-256/256 core as the PRG.

Protocol parameters: `lambda=128`, `lambda_f=160`, `lambda_iv=256`,
`lambda_prg=256`, `ell=1808`, `tau=14`, `w_grind=7`, `T_open=131`, `B=16`,
`d=3`, and `ell_hat=2304` bits (`288` bytes).

## Directory Structure

```
.
├── KAT_SIG.c                              # KAT vector generator entry
├── Makefile                               # Portable C build rules
├── README.md                              # This document
├── auxfunc.c / auxfunc.h                  # API Hash/XOF helper interface
├── bavc.c / bavc.h                        # BAVC commit/reconstruct
├── bench_cycles.h                         # Cycle-counter and stats helpers
├── compat.c / compat.h                    # Compatibility wrappers
├── drng.c / drng.h                        # Deterministic RNG used by KAT/bench
├── endian_compat.h                        # Endian helpers/macros
├── fallbacks.h                            # Feature fallback defines
├── fields.c / fields.h                    # Portable GF arithmetic
├── macros.h                               # Shared macros
├── owf.c / owf.h                          # One-way function helpers
├── params.c / params.h                    # Parameter set definitions
├── prg.c / prg.h                          # Portable Ballet PRG interface
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
├── utils_ballet/                          # Portable Ballet-256/256 components
├── utils_sm4/                             # Portable SM4 components
├── vole.c / vole.h                        # VOLE protocol logic
└── output/                                # Generated KAT output
```

## Requirements

- GCC >= 7
- GNU Make
- C11 runtime (`-lm`)

## Build

Default build is release:

```bash
make sm4th_d3_128s_tight_bench
```

`make` and `make REF_USE_LOOKUP_TABLES=0` use the default table-free
Reference cipher/proof helpers. `make REF_USE_LOOKUP_TABLES=1` explicitly
selects the legacy lookup-table path.

Build settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `NDEBUG` | `1` | `1`: release (`-O3 -DNDEBUG` with LTO), `0`: keep base `-O2` flags |
| `REF_USE_LOOKUP_TABLES` | `0` | `0`: table-free cipher/proof helpers; `1`: legacy lookup-table path |
| `USE_BALLET` / `HAVE_BALLET_CORE` | enabled | Fixed in `CFLAGS`; builds the portable Ballet-256/256 PRG core |

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
The script builds `KAT_SIG` with `NDEBUG=1`.
To generate KATs with an explicit lookup mode, build and run the target directly:

```bash
make NDEBUG=1 REF_USE_LOOKUP_TABLES=1 KAT_SIG
./KAT_SIG
```

From the repository root, compare Optimized/Reference/Test_Vectors hashes with:

```bash
bash Chinith/Implementations/check_kat_hash.sh --variant sm4th_d3_128s_tight
```
