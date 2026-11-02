CC ?= gcc

# Reference implementation: portable C only, no instruction-set acceleration sources or flags.
CFLAGS = -O2 -std=c11 -pedantic -Wall -Wextra -I. -I./utils_vistrutah -include fallbacks.h
# Opt in to legacy lookup tables with REF_USE_LOOKUP_TABLES=1.
REF_USE_LOOKUP_TABLES ?= 0
LDFLAGS = -lm

NDEBUG ?= 1
# Match Optimized LTO in release builds using the selected compiler.
LTO_FLAG := -flto
ifeq (,$(findstring clang,$(shell $(CC) --version 2>/dev/null)))
LTO_FLAG := -flto=auto
endif
ifeq ($(NDEBUG),1)
CFLAGS += -DNDEBUG -O3 $(LTO_FLAG)
endif

# Append lookup mode last so release/debug CFLAGS remain effective.
override CFLAGS += -DREF_USE_LOOKUP_TABLES=$(REF_USE_LOOKUP_TABLES)

SOURCES = auxfunc.c bavc.c compat.c drng.c fields.c params.c prg.c random_oracle.c sig_impl.c universal_hashing.c utils.c utils_vistrutah/sig_impl_vistrutith.c utils_vistrutah/vistrutah.c utils_vistrutah/vistrutith_constraints.c utils_vistrutah/vistrutith_vistrutah_512.c utils_vistrutah/vistrutith_witness.c vistrutith_d3_512s.c vistrutith_d3_512s_AlgorithmInstance.c vole.c 
OBJECTS = $(SOURCES:.c=.o)

all: vistrutith_d3_512s_bench

# The fixed domain is private to sig_impl.c in SOURCES.
# Track the existing initialization and build-option headers.
KAT_SIG: KAT_SIG.c $(SOURCES) compat.h macros.h
	$(CC) $(CFLAGS) -o $@ KAT_SIG.c $(SOURCES) $(LDFLAGS)

vistrutith_d3_512s_bench: vistrutith_d3_512s_bench.c $(SOURCES) compat.h macros.h
	$(CC) $(CFLAGS) -o $@ vistrutith_d3_512s_bench.c $(SOURCES) $(LDFLAGS)

clean:
	rm -f vistrutith_d3_512s_bench vistrutith_d3_512s_test KAT_SIG $(OBJECTS)
	rm -f *.o */*.o
	rm -rf output

.PHONY: all clean KAT_SIG vistrutith_d3_512s_bench
