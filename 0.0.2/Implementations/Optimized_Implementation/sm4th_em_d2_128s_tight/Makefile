CC ?= gcc

# Optimized implementation: maximum performance on x86-64 with SM4 and non-hash ISA acceleration.
# All source files are self-contained in this directory.
CFLAGS = -O3 -std=c11 -pedantic -Wall -Wextra \
         -I. -I./utils_sm4 -I./utils_ballet \
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

# Portable secret-indexed lookup tables require explicit opt-in.
# Honor an explicitly selected legacy switch unless the new switch is set.
ifneq ($(origin USE_SBOX_TABLE),undefined)
REF_USE_LOOKUP_TABLES ?= $(USE_SBOX_TABLE)
else
REF_USE_LOOKUP_TABLES ?= 0
endif
USE_SBOX_TABLE ?= $(REF_USE_LOOKUP_TABLES)
ifeq ($(USE_SBOX_TABLE),1)
CFLAGS += -DSBOX_TABLE -DSM4_SBOX_TABLE
endif

# Ballet PRG AVX2 acceleration. SM4 is used only for the OWF in this tight
# variant, so PRG_ACCE must not pull in SM4 PRG backends.
ifneq (,$(filter x86_64 i386 i486 i586 i686,$(TARGET_ARCH)))
PRG_ACCE ?= 1
else
PRG_ACCE ?= 0
endif
CFLAGS += -DPRG_ACCE=$(PRG_ACCE)
CFLAGS += -DUSE_BALLET=1 -DHAVE_BALLET_CORE=1

# SM4NI acceleration for the single SM4 OWF. Keep this separate from PRG_ACCE:
# tight uses Ballet as PRG and must not pull in SM4 PRG-specific backends.
ifneq (,$(filter x86_64 i386 i486 i586 i686,$(TARGET_ARCH)))
SM4_OWF_ACCE ?= 1
else
SM4_OWF_ACCE ?= 0
endif
CFLAGS += -DSM4TH_ENABLE_SM4_ACCE=$(SM4_OWF_ACCE)

# Native SM4 is independent of AES-NI and Ballet switches.
ifneq (,$(filter x86_64,$(TARGET_ARCH)))
INTEL_SM4_ACCE ?= 1
else
INTEL_SM4_ACCE ?= 0
endif
CFLAGS += -DSM4TH_ENABLE_INTEL_SM4=$(INTEL_SM4_ACCE)

X86_ASM_SOURCE =
X86_ASM_OBJECT =
ifneq ($(X86_64_LINUX),)
ifeq ($(SM4_OWF_ACCE),1)
X86_ASM_SOURCE = utils_sm4/sm4_asm.S
X86_ASM_OBJECT = sm4_asm.o
endif
endif


ifneq ($(X86_ASM_OBJECT),)
$(X86_ASM_OBJECT): $(X86_ASM_SOURCE)
	$(CC) -c -x assembler-with-cpp -o $@ $<
endif

COMMON_SRCS = \
  auxfunc.c bavc.c compat.c drng.c fields.c owf.c params.c prg.c \
  random_oracle.c sig_impl.c sig_timing.c universal_hashing.c utils.c vole.c

UTILS_SM4_SRCS = \
  utils_sm4/sm4_affine.c utils_sm4/sm4_core.c utils_sm4/sm4_sbox.c \
  sm4_witness.c utils_sm4/sm4_ecb.c \
  sm4th_sm4_128.c

BALLET_SRCS = \
  utils_ballet/Ballet256256_coreE.c

INSTANCE_SRCS = \
  sm4th_em_d2_128s_tight.c sm4th_em_d2_128s_tight_AlgorithmInstance.c

SOURCES = $(COMMON_SRCS) $(UTILS_SM4_SRCS) \
          $(BALLET_SRCS) \
          $(INSTANCE_SRCS)
OBJECTS = $(SOURCES:.c=.o)

all: sm4th_em_d2_128s_tight_bench

KAT_SIG: KAT_SIG.c $(SOURCES) $(X86_ASM_OBJECT)
	$(CC) $(CFLAGS) -o $@ KAT_SIG.c $(SOURCES) $(X86_ASM_OBJECT) $(LDFLAGS)

sm4th_em_d2_128s_tight_bench: sm4th_em_d2_128s_tight_bench.c $(SOURCES) $(X86_ASM_OBJECT)
	$(CC) $(CFLAGS) -o $@ sm4th_em_d2_128s_tight_bench.c $(SOURCES) $(X86_ASM_OBJECT) $(LDFLAGS)

clean:
	rm -f sm4th_em_d2_128s_tight_bench sm4th_em_d2_128s_tight_test KAT_SIG \
	      $(X86_ASM_OBJECT) $(OBJECTS)
	rm -f *.o utils_sm4/*.o utils_ballet/*.o utils_ublock/*.o utils_vistrutah/*.o
	rm -rf output

.PHONY: all clean KAT_SIG sm4th_em_d2_128s_tight_bench

# Append after all NDEBUG/ISA flags so override does not suppress them.
override CFLAGS += -DREF_USE_LOOKUP_TABLES=$(REF_USE_LOOKUP_TABLES)
