# ublockith-d3-256f — Optimized Implementation

Optimized implementation of **ublockith-d3-256f**.

Key policy for this target:
- PRG is fixed to **Ballet** (`USE_BALLET=1`).
- `PRG_ACCE` default is **1** (x86 uses AVX2 parallel-enc for Ballet-256/256).
- Bit-exact is preserved by executing the same Ballet encryption round equations as the portable coreE path.
- No SM4/AES path in this target (`UBLOCKITH_ENABLE_SM4_ACCE=0`).

## Directory Structure

```
.
├── KAT_SIG.c                                  # KAT vector generator entry
├── Makefile                                   # Build rules (x86/non-x86 defaults)
├── README.md                                  # This document
├── auxfunc.c / auxfunc.h                      # Portable hash helper interface
├── bavc.c / bavc.h                            # BAVC commit/reconstruct logic
├── bench_cycles.h                         # Hardware cycle-counter helpers
├── compat.c / compat.h                        # Compatibility wrappers
├── drng.c / drng.h                            # Deterministic RNG for KAT/bench
├── endian_compat.h                            # Endian helpers/macros
├── fallbacks.h                                # Platform fallback defines
├── fields.c / fields.h                        # GF arithmetic (optional PCLMUL on x86)
├── macros.h                                   # Shared macros
├── owf.c / owf.h                              # One-way function helpers
├── params.c / params.h                        # Parameter-set definitions
├── prg.c / prg.h                              # PRG interface/implementation (Ballet)
├── random_oracle.c / random_oracle.h          # Random-oracle / transcript hashing
├── run_kat_sig.sh                             # KAT runner script
├── sig_impl.c / sig_impl.h / sig_impl_internal.h # Core sign/verify implementation
├── ublockith_d3_256f.c / .h                   # Public API wrapper
├── ublockith_d3_256f_AlgorithmInstance.c / .h # Algorithm instance entry points
├── ublockith_d3_256f_bench.c                  # Benchmark entry (ms + Mcyc)
├── universal_hashing.c / .h                   # VOLE universal hashing
├── utils.c / utils.h                          # Common utility helpers
├── vole.c / vole.h                            # VOLE protocol logic
├── x86_caps.h                                 # x86 feature detection helpers
├── utils_ballet/
│   ├── BalletDef.h                            # Ballet shared definitions
│   └── Ballet256256_coreE.c / .h              # Ballet-256/256 coreE backend
└── utils_ublock/
    ├── ublock.h                               # uBlock public declarations
    ├── ublock_internal.h                      # uBlock internal declarations
    ├── ublock_core.c                          # uBlock round core
    ├── ublock_affine.c                        # uBlock affine helpers
    ├── ublock_witness.c                       # uBlock witness generation
    ├── ublock_constraints.c / .h              # uBlock constraint system
    ├── ublock_ecb.c                           # uBlock ECB wrapper
    ├── ublockith_ublock_256.c / .h            # ublockith-specific uBlock wrapper
    └── sig_impl_ublock.c                      # ublockith sign/verify backend
```

## Build

Default build is release:

```bash
make ublockith_d3_256f_bench
```

`make` and `make REF_USE_LOOKUP_TABLES=0` select the default table-free
cipher/proof helpers. `make REF_USE_LOOKUP_TABLES=1` explicitly enables the
legacy lookup-table path.

Build options:

| Variable | Default | Description |
|----------|---------|-------------|
| `NDEBUG` | `1` | `1`: release (`-O3 -DNDEBUG`); this family does not use LTO |
| `NATIVE_OPT` | `1` on x86, `0` otherwise | Adds `-march=native` in release builds |
| `REF_USE_LOOKUP_TABLES` | `0` | `0`: table-free cipher/proof helpers; `1`: legacy lookup-table path |
| `PRG_ACCE` | `1` on x86, `0` otherwise | Compile the AVX2 Ballet PRG path |
| `FIELD_PCLMUL` | `1` on x86, `0` otherwise | Compile x86 PCLMUL field acceleration |

`USE_BALLET=1`, `HAVE_BALLET_CORE=1` and `UBLOCKITH_ENABLE_SM4_ACCE=0`
are fixed for this target. The x86 build uses the selected AVX2/PCLMUL
instructions and must run on a compatible CPU.

## Run

Benchmark:

```bash
./ublockith_d3_256f_bench
./ublockith_d3_256f_bench 100 0
./ublockith_d3_256f_bench 100 8
./ublockith_d3_256f_bench 100 0 --all
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

KAT output is written to `output/KAT_SIG_ublockith_d3_256f.txt`.
To generate KATs with an explicit lookup mode, build and run the target directly:

```bash
make NDEBUG=1 REF_USE_LOOKUP_TABLES=1 KAT_SIG
./KAT_SIG
```

From the repository root, compare Optimized/Reference/Test_Vectors hashes with:

```bash
bash Chinith/Implementations/check_kat_hash.sh --variant ublockith_d3_256f
```
