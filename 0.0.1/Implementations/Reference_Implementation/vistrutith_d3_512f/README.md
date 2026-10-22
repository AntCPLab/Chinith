# vistrutith-d3-512f - Reference Implementation

Portable C reference implementation of **vistrutith-d3-512f**. This directory
intentionally contains no instruction-set acceleration sources, backend probes,
or acceleration build flags. The OWF and PRG use the portable Vistrutah path.

Protocol parameters: `lambda=512`, `ell=6912`, `tau=64`, `w_grind=8`,
`T_open=481`, `B=16`, `d=3`.

## Directory Structure

```
.
├── KAT_SIG.c                              # KAT vector generator entry
├── Makefile                               # Portable C build rules
├── README.md                              # This document
├── auxfunc.c / auxfunc.h                  # Hash helper interface
├── bavc.c / bavc.h                        # BAVC commit/reconstruct logic
├── bench_cycles.h                         # Cycle-counter and stats helpers
├── compat.c / compat.h                    # Compatibility wrappers
├── drng.c / drng.h                        # Deterministic RNG for KAT/bench
├── endian_compat.h                        # Endian helpers/macros
├── fallbacks.h                            # Platform fallback defines
├── fields.c / fields.h                    # Portable GF arithmetic
├── macros.h                               # Shared macros
├── owf.h                                  # OWF macro wrapper
├── params.c / params.h                    # Parameter-set definitions
├── prg.c / prg.h                          # Portable Vistrutah PRG interface
├── random_oracle.c / random_oracle.h      # RO / transcript hashing helpers
├── run_kat_sig.sh                         # KAT runner script
├── sig_impl.c / sig_impl.h                # Core sign/verify implementation
├── sig_impl_internal.h                    # Internal sig implementation types
├── vistrutith_d3_512f.c / .h              # Public API wrapper
├── vistrutith_d3_512f_AlgorithmInstance.c / .h # Algorithm instance entry points
├── vistrutith_d3_512f_bench.c             # Benchmark entry
├── universal_hashing.c / .h               # VOLE universal hashing
├── utils.c / utils.h                      # Common utility helpers
├── utils_vistrutah/                       # Portable Vistrutah components and constraints
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
make vistrutith_d3_512f_bench
```

Build settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `NDEBUG` | `1` | `1`: release (`-O3`), `0`: keep base `-O2` flags |
| `SBOX_TABLE` | enabled | Fixed in `CFLAGS`; uses the portable table-based Vistrutah S-box path |

## Run

Benchmark:

```bash
./vistrutith_d3_512f_bench
./vistrutith_d3_512f_bench 100
./vistrutith_d3_512f_bench 100 0
./vistrutith_d3_512f_bench 100 8
```

`./vistrutith_d3_512f_bench` runs 100 fixed-56-byte sign/verify iterations by
default. The optional second argument is `MESSAGE_STEP`; use `0` explicitly for
fixed-56-byte table runs, and `8` for increasing message lengths
`56, 64, 72, ...`. This pure-C Reference path can be slow.

KAT:

```bash
bash run_kat_sig.sh
```

`run_kat_sig.sh` builds `KAT_SIG` with `NDEBUG=1`, runs it, and writes output to
`output/`. Reference Vistrutith KAT generation can take several minutes.
