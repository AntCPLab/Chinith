CC ?= gcc

# Optimized implementation: maximum performance on x86-64 with SM4 and non-hash ISA acceleration.
# All source files are self-contained in this directory.
CFLAGS = -O3 -std=c11 -pedantic -Wall -Wextra \
         -I. -I./utils_sm4 \
         -include fallbacks.h
LDFLAGS = -lm
.DEFAULT_GOAL := all

TARGET_TRIPLE := $(shell $(CC) -dumpmachine)
TARGET_ARCH := $(firstword $(subst -, ,$(TARGET_TRIPLE)))
X86_64_LINUX := $(if $(filter x86_64,$(TARGET_ARCH)),$(findstring linux,$(TARGET_TRIPLE)))

NDEBUG ?= 1
LTO_FLAG := -flto
ifeq (,$(findstring clang,$(shell $(CC) --version 2>/dev/null)))
LTO_FLAG := -flto=auto
endif
ifeq ($(NDEBUG),1)
# Keep the binary baseline-safe; ISA kernels use local targets.
CFLAGS += -DNDEBUG $(LTO_FLAG)
# Retain host scheduling without enabling any global ISA.
ifneq (,$(filter x86_64 i386 i486 i586 i686,$(TARGET_ARCH)))
X86_TUNE := $(shell $(CC) -mtune=native -x c -c /dev/null -o /dev/null >/dev/null 2>&1 && echo -mtune=native)
CFLAGS += $(X86_TUNE)
endif
endif

TIMING ?= 0
COMPONENT_TIMING ?= $(TIMING)
COMPONENT_TIMING_VERBOSE ?= 0
ifeq ($(COMPONENT_TIMING),1)
CFLAGS += -D_POSIX_C_SOURCE=200809L -DSM4TH_COMPONENT_TIMING=1
endif
ifeq ($(COMPONENT_TIMING_VERBOSE),1)
CFLAGS += -DSM4TH_COMPONENT_TIMING_VERBOSE=1
endif

# Compile optional carryless-multiply kernels, select at runtime.
# Default on for x86-64, off otherwise.
ifneq (,$(filter x86_64,$(TARGET_ARCH)))
FIELD_PCLMUL ?= 1
else
FIELD_PCLMUL ?= 0
endif
ifeq ($(FIELD_PCLMUL),1)
CFLAGS += -DSM4TH_FIELD_PCLMUL
endif

# Default to no secret-indexed tables; retain the legacy opt-in switch.
ifneq ($(origin USE_SBOX_TABLE),undefined)
REF_USE_LOOKUP_TABLES ?= $(USE_SBOX_TABLE)
else
REF_USE_LOOKUP_TABLES ?= 0
endif
USE_SBOX_TABLE ?= $(REF_USE_LOOKUP_TABLES)
ifeq ($(USE_SBOX_TABLE),1)
CFLAGS += -DSBOX_TABLE -DSM4_SBOX_TABLE
endif

# SM4 assembly acceleration (sources under utils_sm4/).
# Default on for x86/x86_64, off otherwise.
ifneq (,$(filter x86_64 i386 i486 i586 i686,$(TARGET_ARCH)))
PRG_ACCE ?= 1
else
PRG_ACCE ?= 0
endif
CFLAGS += -DPRG_ACCE=$(PRG_ACCE) -DSM4TH_ENABLE_SM4_ACCE=$(PRG_ACCE)

# Native SM4 is independent of AES-NI and Ballet switches.
ifneq (,$(filter x86_64,$(TARGET_ARCH)))
INTEL_SM4_ACCE ?= 1
else
INTEL_SM4_ACCE ?= 0
endif
CFLAGS += -DSM4TH_ENABLE_INTEL_SM4=$(INTEL_SM4_ACCE)

# Hygon assembly is x86-64 ELF only and runtime gated.
HYGON_SM4_ACCE ?= 0
HYGON_CIS_SRCS =
HYGON_CIS_ASM_SOURCE =
HYGON_CIS_ASM_OBJECT =
ifneq ($(X86_64_LINUX),)
ifeq ($(HYGON_SM4_ACCE),1)
CFLAGS += -D_POSIX_C_SOURCE=200809L -DSM4TH_ENABLE_HYGON_CIS=1
HYGON_CIS_SRCS = utils_sm4/hygon_cis_sm4.c
HYGON_CIS_ASM_SOURCE = utils_sm4/hygon_cis_sm4_asm.S
HYGON_CIS_ASM_OBJECT = hygon_cis_sm4_asm.o
else
CFLAGS += -DSM4TH_ENABLE_HYGON_CIS=0
endif
else
CFLAGS += -DSM4TH_ENABLE_HYGON_CIS=0
endif

# Existing assembly requires the x86-64 ELF ABI.
X86_ASM_SOURCE =
X86_ASM_OBJECT =
ifneq ($(X86_64_LINUX),)
ifeq ($(PRG_ACCE),1)
X86_ASM_SOURCE = utils_sm4/sm4_asm.S
X86_ASM_OBJECT = sm4_asm.o
endif
endif

ifneq ($(HYGON_CIS_ASM_OBJECT),)
$(HYGON_CIS_ASM_OBJECT): $(HYGON_CIS_ASM_SOURCE)
	$(CC) -c -x assembler-with-cpp -o $@ $<
endif

# Append only after NDEBUG and ISA options so all build flags survive.
override CFLAGS += -DREF_USE_LOOKUP_TABLES=$(REF_USE_LOOKUP_TABLES)

COMMON_SRCS = \
  auxfunc.c bavc.c compat.c drng.c fields.c owf.c params.c prg.c \
  random_oracle.c sig_impl.c sig_timing.c universal_hashing.c utils.c vole.c

UTILS_SM4_SRCS = \
  utils_sm4/sm4_affine.c utils_sm4/sm4_core.c utils_sm4/sm4_sbox.c \
  sm4_witness.c utils_sm4/sm4_ecb.c \
  sm4th_sm4_128.c \
  $(HYGON_CIS_SRCS)

INSTANCE_SRCS = \
  sm4th_em_d2_128s_loose.c sm4th_em_d2_128s_loose_AlgorithmInstance.c

SOURCES = $(COMMON_SRCS) $(UTILS_SM4_SRCS) \
          $(INSTANCE_SRCS)
OBJECTS = $(SOURCES:.c=.o)

all: sm4th_em_d2_128s_loose_bench

ifneq ($(X86_ASM_OBJECT),)
$(X86_ASM_OBJECT): $(X86_ASM_SOURCE)
	$(CC) -c -x assembler-with-cpp -o $@ $<
endif

# Existing headers control domains, initialization and table mode.
KAT_SIG: KAT_SIG.c $(SOURCES) compat.h macros.h $(X86_ASM_OBJECT) $(HYGON_CIS_ASM_OBJECT)
	$(CC) $(CFLAGS) -o $@ KAT_SIG.c $(SOURCES) $(X86_ASM_OBJECT) $(HYGON_CIS_ASM_OBJECT) $(LDFLAGS)

sm4th_em_d2_128s_loose_bench: sm4th_em_d2_128s_loose_bench.c $(SOURCES) compat.h macros.h $(X86_ASM_OBJECT) $(HYGON_CIS_ASM_OBJECT)
	$(CC) $(CFLAGS) -o $@ sm4th_em_d2_128s_loose_bench.c $(SOURCES) $(X86_ASM_OBJECT) $(HYGON_CIS_ASM_OBJECT) $(LDFLAGS)

ifneq ($(HYGON_CIS_ASM_OBJECT),)
hygon_cis_sm4_probe: hygon_cis_sm4_probe.c $(HYGON_CIS_SRCS) $(HYGON_CIS_ASM_OBJECT)
	$(CC) $(CFLAGS) -o $@ hygon_cis_sm4_probe.c $(HYGON_CIS_SRCS) $(HYGON_CIS_ASM_OBJECT) $(LDFLAGS)
else
hygon_cis_sm4_probe:
	@echo "Use: make PRG_ACCE=0 HYGON_SM4_ACCE=1 hygon_cis_sm4_probe"
	@exit 1
endif

clean:
	rm -f sm4th_em_d2_128s_loose_bench sm4th_em_d2_128s_loose_test KAT_SIG \
	      hygon_cis_sm4_probe $(X86_ASM_OBJECT) $(HYGON_CIS_ASM_OBJECT) $(OBJECTS)
	rm -f *.o utils_sm4/*.o utils_ballet/*.o utils_ublock/*.o utils_vistrutah/*.o
	rm -rf output

.PHONY: all clean KAT_SIG sm4th_em_d2_128s_loose_bench hygon_cis_sm4_probe
