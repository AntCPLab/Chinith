CC ?= gcc

# Reference implementation: portable C only, no instruction-set acceleration sources or flags.
CFLAGS = -O2 -std=c11 -pedantic -Wall -Wextra -I. -I./utils_ballet -I./utils_sm4 -include fallbacks.h -DSM4_SBOX_TABLE
CFLAGS += -DUSE_BALLET=1 -DHAVE_BALLET_CORE=1
LDFLAGS = -lm

NDEBUG ?= 1
LTO_FLAG := -flto
ifeq (,$(findstring clang,$(shell $(CC) --version 2>/dev/null)))
LTO_FLAG := -flto=auto
endif
ifeq ($(NDEBUG),1)
CFLAGS += -DNDEBUG -O3 $(LTO_FLAG)
endif

SOURCES = auxfunc.c bavc.c compat.c drng.c fields.c owf.c params.c prg.c random_oracle.c sig_impl.c sig_timing.c sm4_witness.c sm4th_d3_128s_tight.c sm4th_d3_128s_tight_AlgorithmInstance.c sm4th_sm4_128.c universal_hashing.c utils.c utils_ballet/Ballet256256_coreE.c utils_sm4/sm4_affine.c utils_sm4/sm4_core.c utils_sm4/sm4_ecb.c utils_sm4/sm4_sbox.c vole.c 
OBJECTS = $(SOURCES:.c=.o)

all: sm4th_d3_128s_tight_bench

KAT_SIG: KAT_SIG.c $(SOURCES)
	$(CC) $(CFLAGS) -o $@ KAT_SIG.c $(SOURCES) $(LDFLAGS)

sm4th_d3_128s_tight_bench: sm4th_d3_128s_tight_bench.c $(SOURCES)
	$(CC) $(CFLAGS) -o $@ sm4th_d3_128s_tight_bench.c $(SOURCES) $(LDFLAGS)

clean:
	rm -f sm4th_d3_128s_tight_bench sm4th_d3_128s_tight_test KAT_SIG $(OBJECTS)
	rm -f *.o */*.o
	rm -rf output

.PHONY: all clean KAT_SIG sm4th_d3_128s_tight_bench
