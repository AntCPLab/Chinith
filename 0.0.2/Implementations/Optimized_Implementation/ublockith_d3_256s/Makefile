CC ?= gcc
IS_X86 := $(filter x86_64 i386 i686,$(shell uname -m))

# Optimized ublockith-d3-256s:
# - Ballet PRG only
# - PRG_ACCE defaults to 1 on x86 (AVX2 parallel-enc over coreE rounds)
# - No SM4/AES code paths in this target
CFLAGS = -O3 -std=c11 -pedantic -Wall -Wextra \
         -I. -I./utils_ublock -I./utils_ballet \
         -include fallbacks.h
LDFLAGS = -lm

# Default to arithmetic secret processing; keep optimized ISA flags independent.
REF_USE_LOOKUP_TABLES ?= 0
TIMING ?= 0
ifeq ($(TIMING),1)
CFLAGS += -DSIG_TIMING -D_POSIX_C_SOURCE=200809L
endif

NDEBUG ?= 1
ifeq ($(IS_X86),)
NATIVE_OPT ?= 0
else
NATIVE_OPT ?= 1
endif
ifeq ($(NDEBUG),1)
ifeq ($(NATIVE_OPT),1)
CFLAGS += -DNDEBUG -march=native
else
CFLAGS += -DNDEBUG -O3
endif
endif

ifneq ($(IS_X86),)
FIELD_PCLMUL ?= 1
else
FIELD_PCLMUL ?= 0
endif
ifeq ($(FIELD_PCLMUL),1)
CFLAGS += -mpclmul -DUBLOCKITH_FIELD_PCLMUL
endif

ifneq ($(IS_X86),)
PRG_ACCE ?= 1
else
PRG_ACCE ?= 0
endif
CFLAGS += -DPRG_ACCE=$(PRG_ACCE) -DUSE_BALLET=1 -DHAVE_BALLET_CORE=1 -DUBLOCKITH_ENABLE_SM4_ACCE=0
ifeq ($(IS_X86),)
CFLAGS += -DUBLOCKITH_REF_PORTABLE=1
endif

BALLET_SRCS = utils_ballet/Ballet256256_coreE.c
ifneq ($(IS_X86),)
ifeq ($(PRG_ACCE),1)
CFLAGS += -mavx2
endif
endif

COMMON_SRCS = \
  auxfunc.c bavc.c compat.c drng.c fields.c owf.c params.c prg.c \
  random_oracle.c sig_impl.c universal_hashing.c utils.c vole.c

UTILS_UBLOCK_SRCS = \
  utils_ublock/ublock_core.c utils_ublock/ublock_affine.c \
  utils_ublock/ublock_witness.c utils_ublock/ublock_constraints.c \
  utils_ublock/ublock_ecb.c utils_ublock/ublockith_ublock_256.c \
  utils_ublock/sig_impl_ublock.c

INSTANCE_SRCS = \
  ublockith_d3_256s.c ublockith_d3_256s_AlgorithmInstance.c

SOURCES = $(COMMON_SRCS) $(UTILS_UBLOCK_SRCS) $(BALLET_SRCS) $(INSTANCE_SRCS)
OBJECTS = $(SOURCES:.c=.o)

# Append last so custom CFLAGS honor this option without suppressing ISA/NDEBUG flags.
override CFLAGS += -DREF_USE_LOOKUP_TABLES=$(REF_USE_LOOKUP_TABLES)

all: ublockith_d3_256s_bench

KAT_SIG: KAT_SIG.c $(SOURCES)
	$(CC) $(CFLAGS) -o $@ KAT_SIG.c $(SOURCES) $(LDFLAGS)

ublockith_d3_256s_bench: ublockith_d3_256s_bench.c $(SOURCES)
	$(CC) $(CFLAGS) -o $@ ublockith_d3_256s_bench.c $(SOURCES) $(LDFLAGS)

field_mul_bench: field_mul_bench.c fields.c
	$(CC) $(CFLAGS) -o $@ field_mul_bench.c fields.c $(LDFLAGS)

clean:
	rm -f ublockith_d3_256s_bench ublockith_d3_256s_test KAT_SIG field_mul_bench \
	      $(OBJECTS)
	rm -f *.o utils_sm4/*.o utils_ballet/*.o utils_ublock/*.o utils_vistrutah/*.o
	rm -rf output

.PHONY: all clean KAT_SIG ublockith_d3_256s_bench field_mul_bench
