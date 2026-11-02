# vistrutith-d3-512s — Optimized Implementation

Optimized implementation of **vistrutith-d3-512s** with x86 AES-NI acceleration for the
Vistrutah PRG path (single-core only, no OpenMP).

Key policy for this target:
- OWF is fixed to `vistrutah_512_encrypt` (see `owf.h`).
- PRG is fixed to `vistrutah_512_encrypt` counter mode (`seclvl=512`, see `prg.c`).
- This directory is self-contained and independent from `Reference_Implementation`.
- On x86, default build enables `PRG_ACCE=1`

## Directory Structure

```text
.
├── KAT_SIG.c                                      # KAT vector generator entry
├── Makefile                                       # Build rules (optimized defaults)
├── README.md                                      # This document
├── auxfunc.c / auxfunc.h                          # Portable hash helper interface
├── bavc.c / bavc.h                                # BAVC commit/reconstruct logic
├── bench_cycles.h                         # Hardware cycle-counter helpers
├── compat.c / compat.h                            # Compatibility wrappers
├── drng.c / drng.h                                # Deterministic RNG for KAT/bench
├── endian_compat.h                                # Endian helpers/macros
├── fallbacks.h                                    # Platform fallback defines
├── fields.c / fields.h                            # GF arithmetic (bf512 and helpers)
├── macros.h                                       # Shared macros
├── owf.h                                          # OWF macro wrapper to vistrutah_512_encrypt
├── params.c / params.h                            # Parameter-set definitions
├── prg.c / prg.h                                  # Vistrutah-based PRG implementation
├── random_oracle.c / random_oracle.h              # Random-oracle / transcript hashing
├── run_kat_sig.sh                                 # KAT runner script
├── sig_impl.c / sig_impl.h / sig_impl_internal.h  # Shared sign/verify transcript logic
├── universal_hashing.c / .h                       # VOLE universal hashing
├── utils.c / utils.h                              # Common utility helpers
├── vole.c / vole.h                                # VOLE protocol logic
├── vistrutith_d3_512s.c / .h                      # Public API wrapper
├── vistrutith_d3_512s_AlgorithmInstance.c / .h    # Algorithm instance entry points
├── vistrutith_d3_512s_bench.c                     # Benchmark entry
├── vistrutith_d3_512s_test.c                      # Basic sign/verify self-test
└── utils_vistrutah/
    ├── vistrutah.h                                # Vistrutah constants + core declarations
    ├── vistrutah.c                                # Unified Vistrutah implementation (portable + x86 AES-NI fast path)
    ├── vistrutith_witness.c / .h                  # Extended witness generation
    ├── vistrutith_constraints.c / .h              # Enc constraints (prover/verifier)
    ├── vistrutith_vistrutah_512.c / .h            # QuickSilver wrapper for constraints
    └── sig_impl_vistrutith.c                      # vistrutith sign/verify backend hook
```

## Requirements

- GCC >= 7 or Clang >= 6
- GNU Make
- C11 runtime (`-lm`)

## Build

Default build is release:

```bash
make vistrutith_d3_512s_bench
```

`make` and `make REF_USE_LOOKUP_TABLES=0` select the default table-free
cipher/proof helpers. `make REF_USE_LOOKUP_TABLES=1` explicitly enables the
legacy lookup-table path.

Build options:

| Variable | Default | Description |
|----------|---------|-------------|
| `NDEBUG` | `1` | `1`: release (`-O3 -DNDEBUG` with LTO), adding `-march=native` on x86 |
| `REF_USE_LOOKUP_TABLES` | `0` | `0`: table-free cipher/proof helpers; `1`: legacy lookup-table path |
| `PRG_ACCE` | `1` on x86, `0` otherwise | Compile the AES-NI Vistrutah path |
| `FIELD_PCLMUL` | `1` on x86, `0` otherwise | Compile x86 PCLMUL field acceleration |

The x86 build uses the selected AES-NI/PCLMUL instructions and must run on a
compatible CPU.

## Run

Self-test:

```bash
make vistrutith_d3_512s_test
./vistrutith_d3_512s_test
```

Benchmark:

```bash
./vistrutith_d3_512s_bench
./vistrutith_d3_512s_bench 100 0
./vistrutith_d3_512s_bench 100 8
./vistrutith_d3_512s_bench 100 0 --all
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

KAT output is written to `output/KAT_SIG_vistrutith_d3_512s.txt`.
To generate KATs with an explicit lookup mode, build and run the target directly:

```bash
make NDEBUG=1 REF_USE_LOOKUP_TABLES=1 KAT_SIG
./KAT_SIG
```

From the repository root, compare Optimized/Reference/Test_Vectors hashes with:

```bash
bash Chinith/Implementations/check_kat_hash.sh --variant vistrutith_d3_512s
```
