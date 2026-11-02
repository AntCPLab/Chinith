# Chinith 实现目录说明

本目录提供14个参数实例的 Reference 和 Optimized 实现、公开KAT向量及一致性检查入口。
编译选项位于各实例现有的 `macros.h`，一次性初始化辅助函数位于 `compat.h`，
固定协议域标识 `Chinith/<协议实例名>` 为 `sig_impl.c` 内的私有常量。
两套实现使用相同协议、密钥和签名格式，当前KAT基准位于 `../Test_Vectors/`。

全部28个实例默认使用 `REF_USE_LOOKUP_TABLES=0`，禁用秘密数据索引的密码／证明辅助查表。
`make REF_USE_LOOKUP_TABLES=1` 可显式选择历史查表路径，协议与KAT格式不变。
该选项不控制NGCC指定的Hash／DRNG后端，也不代表完整的侧信道安全认证。

## 目录结构

```text
Chinith/
├── Test_Vectors/
│   ├── KAT_SIG_sm4th_d3_128f_loose.txt
│   ├── KAT_SIG_sm4th_d3_128f_tight.txt
│   ├── KAT_SIG_sm4th_d3_128s_loose.txt
│   ├── KAT_SIG_sm4th_d3_128s_tight.txt
│   ├── KAT_SIG_sm4th_em_d2_128f_loose.txt
│   ├── KAT_SIG_sm4th_em_d2_128f_tight.txt
│   ├── KAT_SIG_sm4th_em_d2_128s_loose.txt
│   ├── KAT_SIG_sm4th_em_d2_128s_tight.txt
│   ├── KAT_SIG_ublockith_d3_256f.txt
│   ├── KAT_SIG_ublockith_d3_256s.txt
│   ├── KAT_SIG_ublockith_em_d3_256f.txt
│   ├── KAT_SIG_ublockith_em_d3_256s.txt
│   ├── KAT_SIG_vistrutith_d3_512f.txt
│   └── KAT_SIG_vistrutith_d3_512s.txt
└── Implementations/
    ├── README.md
    ├── check_kat_hash.sh
    ├── Optimized_Implementation/
    │   ├── sm4th_d3_128f_loose/
    │   ├── sm4th_d3_128f_tight/
    │   ├── sm4th_d3_128s_loose/
    │   ├── sm4th_d3_128s_tight/
    │   ├── sm4th_em_d2_128f_loose/
    │   ├── sm4th_em_d2_128f_tight/
    │   ├── sm4th_em_d2_128s_loose/
    │   ├── sm4th_em_d2_128s_tight/
    │   ├── ublockith_d3_256f/
    │   ├── ublockith_d3_256s/
    │   ├── ublockith_em_d3_256f/
    │   ├── ublockith_em_d3_256s/
    │   ├── vistrutith_d3_512f/
    │   └── vistrutith_d3_512s/
    └── Reference_Implementation/
        ├── sm4th_d3_128f_loose/
        ├── sm4th_d3_128f_tight/
        ├── sm4th_d3_128s_loose/
        ├── sm4th_d3_128s_tight/
        ├── sm4th_em_d2_128f_loose/
        ├── sm4th_em_d2_128f_tight/
        ├── sm4th_em_d2_128s_loose/
        ├── sm4th_em_d2_128s_tight/
        ├── ublockith_d3_256f/
        ├── ublockith_d3_256s/
        ├── ublockith_em_d3_256f/
        ├── ublockith_em_d3_256s/
        ├── vistrutith_d3_512f/
        └── vistrutith_d3_512s/
```

## 参数目录命名

- `sm4th_*`：以 SM4 相关 OWF/约束为核心的 128-bit 经典安全签名族。
- `ublockith_*`：以 uBlock 相关 OWF/约束为核心的 256-bit 经典安全签名族。
- `vistrutith_*`：以 Vistrutah 相关 OWF/约束为核心的 512-bit 经典安全签名族。
- `*_em_*`：以 Even-Mansour 构造为 OWF 的变体参数集。
- `*_loose` / `*_tight`：SM4th 的 loose/tight 参数化版本。
- 末尾 `s` / `f`：同一族内的 small/fast 性能取舍。

## Test_Vectors

`../Test_Vectors/` 保存当前提交版本认可的 KAT 基准文件。每个文件对应一个活动实例，实例名 `<scheme>` 与 `Implementations/Optimized_Implementation/<scheme>/`、`Implementations/Reference_Implementation/<scheme>/` 目录名保持一致。

当前覆盖 14 个实例：

- SM4th loose/tight：`sm4th_d3_128{s,f}_{loose,tight}`、`sm4th_em_d2_128{s,f}_{loose,tight}`。
- uBlockith：`ublockith_d3_256{s,f}`、`ublockith_em_d3_256{s,f}`。
- Vistrutith：`vistrutith_d3_512{s,f}`。

单个实例的 KAT 输出由该实例目录下的 `run_kat_sig.sh` 生成到本地 `output/` 目录：

```text
Implementations/<Implementation>/<scheme>/output/KAT_SIG_<scheme>.txt
```

当协议参数、实现逻辑或 KAT 格式发生预期变化时，应重新生成 Optimized 与 Reference 的 KAT 输出，同步更新 `../Test_Vectors/KAT_SIG_<scheme>.txt`，再运行 `check_kat_hash.sh` 确认三者一致。

## KAT 检查脚本

`check_kat_hash.sh` 是本目录的统一 KAT 一致性入口。默认行为是：

1. 对选中的实例分别运行 Optimized 与 Reference 目录中的 `run_kat_sig.sh`。
2. 读取两套实现生成的 `output/KAT_SIG_<scheme>.txt`。
3. 读取 `../Test_Vectors/KAT_SIG_<scheme>.txt`。
4. 输出三者的 SHA256，并检查 Optimized、Reference、`Test_Vectors` 是否完全一致。

从 `Chinith/Implementations/` 目录运行：

```bash
./check_kat_hash.sh
```

或从仓库根目录运行：

```bash
bash Chinith/Implementations/check_kat_hash.sh
```

常用参数：

- `--variant <scheme>` 或直接追加 `<scheme>`：只检查指定实例，可重复传入。
- `--hash-only` / `--no-run-kats`：跳过 KAT 生成，只比较已有 `output/` 与 `../Test_Vectors/` 文件。
- `--run-kats`：显式启用 KAT 生成。
- `CHECK_KAT_HASH_RUN_KATS=0`：通过环境变量默认进入 hash-only 模式。
- `-h` / `--help`：显示脚本帮助。

示例：

```bash
./check_kat_hash.sh --variant sm4th_d3_128s_loose
./check_kat_hash.sh --hash-only ublockith_d3_256f vistrutith_d3_512s
CHECK_KAT_HASH_RUN_KATS=0 ./check_kat_hash.sh
```

全部通过时会输出：

```text
[PASS] All requested KAT hash checks passed.
```

## 单个实例目录

下面的说明适用于任意一个实例目录，例如 `Implementations/Optimized_Implementation/sm4th_d3_128f_loose/`。

### 构建与入口文件

- `Makefile`：该实例的构建规则。
- `README.md`：该实例的局部说明。
- `run_kat_sig.sh`：KAT 生成脚本。
- `KAT_SIG.c`：KAT 程序入口。
- `<scheme>_bench.c`：benchmark 入口，支持独立的速度与内存进程。
- `bench_cycles.h`：硬件周期计数与统计辅助。
- `<scheme>_AlgorithmInstance.c/.h`：签名 API 适配与实例入口。

### 协议核心文件

- `sig_impl.c/.h`：签名与验证主流程。
- `sig_impl_internal.h`：内部上下文、结构和辅助声明。
- `params.c/.h`：实例参数和派生长度。
- `prg.c/.h`：PRG 接口与实现。
- `random_oracle.c/.h`：用于Random oracle 的哈希函数。
- `bavc.c/.h`：BAVC commit/open/reconstruct 逻辑。
- `universal_hashing.c/.h`：universal 哈希模块。
- `vole.c/.h`：VOLE 相关逻辑。
- `fields.c/.h`：有限域运算。
- `auxfunc.c/.h`：Hash/XOF 辅助接口，由提交 API 提供。
- `drng.c/.h`：确定性随机数工具。
- `compat.c/.h`：跨平台/编译器兼容层。
- `utils.c/.h`：通用工具函数。
- `macros.h`：公共宏定义。
- `endian_compat.h`：大小端与字节序辅助。
- `fallbacks.h`：特性缺失时的回退定义。
- `owf.c/.h` 或 `owf.h`：OWF 封装。

其中，`random_oracle`、`bavc`、`universal_hashing`、`vole`、`fields`、`compat`、`utils`、`macros`、`endian_compat` 等文件中的部分函数和逻辑参考了签名 FAEST 的开源代码：
https://github.com/faest-sign/faest-ref

该开源代码的版权说明如下。

Copyright (c) 2023 Sebastian Ramacher, AIT Austrian Institute of Technology

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## 优化实现

SM4实例的可选指令内核保存在已有的 `utils_sm4/sm4_ecb.c`、`prg.c` 等文件中，
运行时通过 `x86_caps.h` 检查CPU与操作系统支持，优先选择原生Intel SM4，
其次选择AES-NI／SSSE3模拟的SM4NI，再回退至便携C路径。
原生SM4内核需GCC 14及以上，或提供 `sm4intrin.h` 的Clang。
loose使用SM4 PRG；tight的PRG保持Ballet，SM4分派用于OWF。

常用构建开关按实例族区分：

| 实例族 | 当前构建方式与开关 |
|---|---|
| 全部实例 | 默认 `NDEBUG=1`，release实际使用 `-O3 -DNDEBUG`；`REF_USE_LOOKUP_TABLES` 默认0，显式1启用查表 |
| Reference | 便携C；SM4／Vistrutith使用LTO，uBlock不使用LTO；`NDEBUG=0` 保留基础 `-O2` 与断言 |
| Optimized SM4 loose | `PRG_ACCE` 控制AES-NI模拟PRG，`INTEL_SM4_ACCE` 独立控制原生SM4；`FIELD_PCLMUL` 控制可选域内核；release使用LTO，可用时加 `-mtune=native` |
| Optimized SM4 tight | `PRG_ACCE` 控制Ballet AVX2，`SM4_OWF_ACCE` 控制SM4 OWF的AES-NI模拟，`INTEL_SM4_ACCE` 独立控制原生SM4；release使用LTO |
| Optimized uBlock | Ballet PRG可选AVX2、域运算可选PCLMUL；不使用LTO；x86的 `NATIVE_OPT=1` 为release加入 `-march=native` |
| Optimized Vistrutith | x86可选AES-NI与PCLMUL；release使用LTO，x86还加入 `-march=native` |

各实例README列出具体默认值。uBlock／Vistrutith的x86构建须在兼容所选指令的CPU上运行。
SM4关闭 `PRG_ACCE` 或 `SM4_OWF_ACCE` 不会同时关闭原生分支；需要时另设 `INTEL_SM4_ACCE=0`。

## 单实例 KAT

在单个实例目录生成KAT：

```bash
bash run_kat_sig.sh
```

输出为 `output/KAT_SIG_<scheme>.txt`。显式选择查表模式时，可直接构建和运行：

```bash
make NDEBUG=1 REF_USE_LOOKUP_TABLES=1 KAT_SIG
./KAT_SIG
```

随后可用 `check_kat_hash.sh --hash-only <scheme>` 比较已有输出与 `../Test_Vectors/`。

## Benchmark

在任意实例目录运行：

```bash
make <scheme>_bench
./<scheme>_bench
./<scheme>_bench 100 0
./<scheme>_bench 100 8
./<scheme>_bench 100 0 --all
```

`N`（第一个参数）默认100，是每个API实际执行的次数，没有内置暖机或自动排除首轮。
第二个参数 `MESSAGE_STEP` 默认0，第 `i` 组消息长度为 `56 + MESSAGE_STEP*i` 字节。
默认表列为 `operation`、`mean ms/op`、`mean cycles/op`、`mean Mcycles/op`，
给出KeyGen、Sign、Verify三项操作的均值，随后输出公钥、私钥、签名字节数。
ms由 `clock()` 测量进程user＋system CPU时间。cycles为用户态硬件CPU周期，
不使用TSC回退或按主频换算；Mcycles为cycles除以10⁶。硬件计数器不可用时输出 `N/A` 及原因。

`--all` 先在全新进程中完成请求的N组速度测量。在Linux上，随后在另一个全新进程中运行
3组完整的KeyGen／Sign／Verify内存测量，3组全部计入。完整模式还输出公钥、私钥、签名尺寸及
所观察到的子进程RSS最大值，包含初始化、全部迭代和可观察的输出／清理，不计父观察器。
这不是每个API各自的峰值，也不是连续时间的绝对峰值；内存轮计时不用于速度结果。
RSS观察需要Linux；macOS执行 `--all` 时成功完成速度测量，并将RSS报告为 `N/A`。

## 构建产物

各实例目录可能出现目标文件 `*.o`、可执行文件 `KAT_SIG`／`*_bench` 及KAT输出目录 `output/`。

```bash
make clean
```

清理该实例的可执行文件、目标文件和 `output/` 等构建产物。
