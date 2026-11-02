# Chinith

Chinith is a family of post-quantum signature schemes — **SM4th**, **uBlockith**, and **Vistrutith** — built from the VOLE-in-the-head (VOLEitH) paradigm and established symmetric-key primitives (block-cipher OWFs plus SM3). Like FAEST, it avoids extra number-theoretic or coding-theoretic assumptions and relies only on well-studied symmetric cryptography, which we view as a more conservative design choice for post-quantum signatures. The schemes target 128 / 256 / 512-bit classical security via SM4, uBlock, and Vistrutah, respectively. Our reference implementation follows the same overall structure and engineering patterns as FAEST, adapted to these Chinese and related block ciphers.

This repository hosts the NGCC Round-1 reference package.

## Authors

Weihan Li, Yuchen Wang, Zhelei Zhou, Cheng Hong, and Tao Wei  
Ant Group,  China

## History

### 0.0.1
The initial NGCC submitted version.

### 0.0.2
NGCC-v0.0.2 author revision from leeweihanwickham/Chinith @ 5b5559e6 (includes Optimized_Implementation + Test_Vectors).

## Layout 

Versioned packages live in `0.0.1/` and `0.0.2/`:

- `Algorithm specifications/` — specification PDF  
- `Implementations/` — portable C implementations (`Reference_Implementation/`; `Optimized_Implementation/` in 0.0.2)
- `Test_Vectors/` — known-answer tests (0.0.2)

| Scheme | Security | Parameter sets |
|--------|----------|----------------|
| SM4th | 128-bit | `sm4th_d3_128{f,s}_{loose,tight}`, `sm4th_em_d2_128{f,s}_{loose,tight}` |
| uBlockith | 256-bit | `ublockith_d3_256{f,s}`, `ublockith_em_d3_256{f,s}` |
| Vistrutith | 512-bit | `vistrutith_d3_512{f,s}` |

## Build

```bash
cd /Implementations/Reference_Implementation/<param_set>
make           
```

We recommend using the [NGCC Provider](https://github.com/Tongsuo-Project/NGCC-provider) tool to test Chinith in OpenSSL/Tongsuo.
