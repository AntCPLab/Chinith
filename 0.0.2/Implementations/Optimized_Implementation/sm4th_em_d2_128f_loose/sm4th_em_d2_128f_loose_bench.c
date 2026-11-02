#include "sm4th_em_d2_128f_loose_AlgorithmInstance.h"
#include "drng.h"
#include "sig_impl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "bench_cycles.h"

#define SEED_LEN_BYTES 64

DRNG_ctx drng_algorithm;

static double seconds_since(clock_t start, clock_t end) {
  return (double)(end - start) / (double)CLOCKS_PER_SEC;
}

/* Measure RSS in a separate run; syscall stops precede memory release. */
static int bench_memory_child = 0;

#if defined(__linux__)
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>

static long bench_memory_read_rss(pid_t child) {
  char path[64], line[256], unit[16];
  if (snprintf(path, sizeof(path), "/proc/%ld/smaps_rollup", (long)child) < 0) {
    return -1;
  }
  FILE* maps = fopen(path, "r");
  if (!maps) {
    return -1;
  }
  long value, rss = -1;
  while (fgets(line, sizeof(line), maps)) {
    if (sscanf(line, "Rss: %ld %15s", &value, unit) == 2 &&
        strcmp(unit, "kB") == 0 && value > 0) {
      rss = value;
      break;
    }
  }
  if (ferror(maps)) {
    rss = -1;
  }
  fclose(maps);
  return rss;
}

static pid_t bench_memory_wait(pid_t child, int* status) {
  pid_t result;
  do {
    result = waitpid(child, status, 0);
  } while (result < 0 && errno == EINTR);
  return result;
}
#endif

static int bench_memory_begin(int enabled) {
  if (!enabled) {
    return 0;
  }
#if defined(__linux__)
  fflush(NULL);
  const pid_t observer = getpid();
  const pid_t child = fork();
  if (child < 0) {
    perror("memory observer fork");
    return -1;
  }
  if (child == 0) {
    /* Cover observer death before ptrace EXITKILL can be installed. */
    if (prctl(PR_SET_PDEATHSIG, (long)SIGKILL, 0L, 0L, 0L) < 0 || getppid() != observer) {
      _exit(EXIT_FAILURE);
    }
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0 || raise(SIGSTOP) != 0) {
      perror("memory observer trace");
      return -1;
    }
    bench_memory_child = 1;
    return 0;
  }

  int status;
  long peak = -1;
  unsigned long samples = 0;
  if (bench_memory_wait(child, &status) != child || !WIFSTOPPED(status)) {
    fprintf(stderr, "memory observation failed before initial stop\n");
    exit(EXIT_FAILURE);
  }
  if (WSTOPSIG(status) != SIGSTOP ||
      ptrace(PTRACE_SETOPTIONS, child, NULL,
             (void*)(uintptr_t)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL |
                               PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK |
                               PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC)) < 0) {
    goto memory_error;
  }
  puts("memory mode: syscall-boundary RSS observation");
  puts("memory timing: omitted from instrumented run");
  fflush(stdout);
  for (;;) {
    const long rss = bench_memory_read_rss(child);
    if (rss < 0) {
      goto memory_error;
    }
    if (rss > peak) {
      peak = rss;
    }
    ++samples;
    int signal_number = 0;
    for (;;) {
      if (ptrace(PTRACE_SYSCALL, child, NULL, (void*)(intptr_t)signal_number) < 0) {
        goto memory_error;
      }
      if (bench_memory_wait(child, &status) != child) {
        fprintf(stderr, "memory observation lost its child\n");
        exit(EXIT_FAILURE);
      }
      if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) != 0 || peak <= 0 || samples < 2) {
          fprintf(stderr, "memory observation failed: benchmark exit %d\n", WEXITSTATUS(status));
          exit(EXIT_FAILURE);
        }
        puts("memory source: /proc/PID/smaps_rollup Rss at ptrace syscall stops");
        puts("memory scope: observed child-process RSS maximum, including setup and all iterations");
        printf("memory samples: %lu\n", samples);
        printf("peak rss: %ld KiB\n", peak);
        exit(EXIT_SUCCESS);
      }
      if (WIFSIGNALED(status)) {
        fprintf(stderr, "memory observation failed: benchmark signal %d\n", WTERMSIG(status));
        exit(EXIT_FAILURE);
      }
      if (!WIFSTOPPED(status)) {
        goto memory_error;
      }
      signal_number = WSTOPSIG(status);
      if (signal_number == (SIGTRAP | 0x80)) {
        break;
      }
      if (signal_number == SIGTRAP || signal_number == SIGSTOP ||
          signal_number == SIGTSTP || signal_number == SIGTTIN ||
          signal_number == SIGTTOU) {
        goto memory_error;
      }
    }
  }

memory_error:
  fprintf(stderr, "memory observation unavailable or incomplete\n");
  /* PTRACE_KILL is unreliable at syscall/event stops; send SIGKILL. */
  {
    long killed;
    do {
      killed = syscall(SYS_kill, (long)child, SIGKILL);
    } while (killed < 0 && errno == EINTR);
    if (killed == 0 || errno == ESRCH) {
      bench_memory_wait(child, &status);
    }
  }
  exit(EXIT_FAILURE);
#else
  fprintf(stderr, "CHINITH_BENCH_MEMORY requires Linux ptrace and smaps_rollup\n");
  return -1;
#endif
}

/* Validate inputs before allocation, tracing, or starting either phase. */
static int bench_parse_size(const char* text, size_t* value) {
  char* end;
  if (text[0] < '0' || text[0] > '9') {
    return -1;
  }
  errno = 0;
  const uintmax_t parsed = strtoumax(text, &end, 10);
  if (errno == ERANGE || *end != '\0' || parsed > SIZE_MAX) {
    return -1;
  }
  *value = (size_t)parsed;
  return 0;
}

static int bench_valid_workload(size_t iterations, size_t step) {
  return iterations > 0 && iterations <= SIZE_MAX / sizeof(long double) &&
      iterations <= (SIZE_MAX - 9u) / 9u &&
      (step == 0 || iterations - 1u <= (SIZE_MAX - 56u) / step);
}

/* Each phase execs a fresh image; no timing allocations enter the RSS run. */
static int bench_run_phase(char* program, size_t iterations, size_t step,
                           int memory, int detailed) {
  char count_text[3 * sizeof(size_t) + 1], step_text[3 * sizeof(size_t) + 1];
  snprintf(count_text, sizeof(count_text), "%zu", iterations);
  snprintf(step_text, sizeof(step_text), "%zu", step);
  char* args[] = {program, count_text, step_text,
                  memory ? "--memory" : (detailed ? "--stats" : NULL), NULL};
  fflush(NULL);
#if defined(__linux__)
  const pid_t parent = getpid();
#endif
  const pid_t child = fork();
  if (child < 0) {
    perror("benchmark phase fork");
    return EXIT_FAILURE;
  }
  if (child == 0) {
#if defined(__linux__)
    /* A timed-out controller must not leave a benchmark running. */
    if (prctl(PR_SET_PDEATHSIG, (long)SIGKILL, 0L, 0L, 0L) < 0 || getppid() != parent) {
      _exit(EXIT_FAILURE);
    }
    execv("/proc/self/exe", args);
#else
    execvp(program, args);
#endif
    perror("benchmark phase exec");
    _exit(127);
  }
  int status;
  pid_t result;
  do {
    result = waitpid(child, &status, 0);
  } while (result < 0 && errno == EINTR);
  if (result != child) {
    perror("benchmark phase wait");
    return EXIT_FAILURE;
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    fprintf(stderr, "%s phase failed\n", memory ? "memory" : "speed");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

static void bench_print_average(const char* label, const double* ms,
                                 const long double* mcyc, size_t count,
                                 int have_cycles) {
  long double total_ms = 0.0L, total_mcyc = 0.0L;
  for (size_t i = 0; i < count; ++i) {
    total_ms += ms[i];
    total_mcyc += mcyc[i];
  }
  printf("%-8s %14.6Lf", label, total_ms / count);
  if (have_cycles) {
    printf(" %18.3Lf %16.6Lf\n", total_mcyc / count * 1000000.0L,
           total_mcyc / count);
  } else {
    printf(" %18s %16s\n", "N/A", "N/A");
  }
}

static void fill_signature_message(unsigned char* message,
                                   unsigned long long message_len,
                                   size_t iteration) {
  static const unsigned char base[] =
      "Chinith sm4th ublockith vistrutith 56-byte bench msg v1.";
  static const unsigned char filler[] =
      " sm4th ublockith vistrutith bench message ";
  const size_t base_len = sizeof(base) - 1;
  const size_t filler_len = sizeof(filler) - 1;
  size_t pos = 0;

  while (pos < message_len && pos < base_len) {
    message[pos] = base[pos];
    pos++;
  }
  while (pos < message_len) {
    message[pos] = filler[(pos + iteration) % filler_len];
    pos++;
  }
}

int main(int argc, char** argv) {
  size_t iterations = 100, message_len_step = 0;
  int all = 0, detailed = 0, positional = 0;
  const char* memory_env = getenv("CHINITH_BENCH_MEMORY");
  int memory = memory_env && strcmp(memory_env, "1") == 0;
  for (int arg = 1; arg < argc; ++arg) {
    if (strcmp(argv[arg], "--all") == 0) {
      all = 1;
    } else if (strcmp(argv[arg], "--stats") == 0) {
      detailed = 1;
    } else if (strcmp(argv[arg], "--memory") == 0) {
      memory = 1; /* Internal exec mode; legacy memory environment still works. */
    } else if (strcmp(argv[arg], "--help") == 0) {
      printf("Usage: %s [iterations>0] [message_step>=0] [--all] [--stats]\n", argv[0]);
      return EXIT_SUCCESS;
    } else if (positional >= 2 ||
               bench_parse_size(argv[arg], positional == 0 ? &iterations : &message_len_step) != 0) {
      fprintf(stderr, "invalid benchmark argument: %s\n", argv[arg]);
      return EXIT_FAILURE;
    } else {
      ++positional;
    }
  }
  if (!bench_valid_workload(iterations, message_len_step) ||
      (all && !bench_valid_workload(3, message_len_step))) {
    fprintf(stderr, "invalid iteration count or overflowing benchmark workload\n");
    return EXIT_FAILURE;
  }
  if (all) {
    if (memory) {
      fprintf(stderr, "--all cannot be combined with a memory-only run\n");
      return EXIT_FAILURE;
    }
    puts("benchmark mode: sequential speed and independent memory phases");
    printf("speed iterations: %zu; warmup excluded: 0\n", iterations);
    if (bench_run_phase(argv[0], iterations, message_len_step, 0, detailed) != 0) {
      return EXIT_FAILURE;
    }
#if defined(__linux__)
    puts("memory iterations: 3 (all included)");
    return bench_run_phase(argv[0], 3, message_len_step, 1, 0);
#else
    puts("memory source: unavailable; requires Linux ptrace and smaps_rollup");
    puts("peak rss: N/A");
    return EXIT_SUCCESS;
#endif
  }
  if (bench_memory_begin(memory) != 0) {
    return EXIT_FAILURE;
  }

  unsigned char* nonce1 = (unsigned char*)calloc(SEED_LEN_BYTES, sizeof(unsigned char));
  if (!nonce1) {
    fprintf(stderr, "nonce allocation failed\n");
    free(nonce1);
    return 1;
  }
  for (int i = 0; i < SEED_LEN_BYTES / 4; i++) {
    memcpy(nonce1 + 4 * i, "seed", 4);
  }
  DRNG_ctx drng_seed;
  if (init_random_number(&drng_seed, nonce1, SEED_LEN_BYTES) != 0) {
    fprintf(stderr, "drng init failed\n");
    free(nonce1);
    return 1;
  }

  const size_t max_message_len = 56 + message_len_step * (iterations - 1);
  unsigned char* seed = (unsigned char*)calloc(SEED_LEN_BYTES, sizeof(unsigned char));
  unsigned char* message = (unsigned char*)calloc(max_message_len, sizeof(unsigned char));
  if (!seed || !message) {
    fprintf(stderr, "seed and message buffer allocation failed\n");
    free(seed);
    free(message);
    free(nonce1);
    return 1;
  }

  unsigned long long pk_len_bytes = sig_get_pk_len_bytes();
  unsigned long long sk_len_bytes = sig_get_sk_len_bytes();
  unsigned long long sn_len_bytes = sig_get_sn_len_bytes();
  unsigned char* pk = (unsigned char*)calloc(pk_len_bytes, sizeof(unsigned char));
  unsigned char* sk = (unsigned char*)calloc(sk_len_bytes, sizeof(unsigned char));
  unsigned char* sn = (unsigned char*)calloc(sn_len_bytes, sizeof(unsigned char));
  if (!pk || !sk || !sn) {
    fprintf(stderr, "key/signature allocation failed\n");
    free(pk);
    free(sk);
    free(sn);
    free(seed);
    free(message);
    free(nonce1);
    return 1;
  }

  bench_iteration_stats_t iter_stats;
  if (bench_iteration_stats_init(&iter_stats, iterations) != 0) {
    fprintf(stderr, "iteration stats allocation failed\n");
    free(pk);
    free(sk);
    free(sn);
    free(seed);
    free(message);
    free(nonce1);
    return 1;
  }

  unsigned long long message_len = 56;
  const int cycles_ok = !bench_memory_child && bench_cycles_available();

  /* silence internal sm4th status prints during bench */

  for (size_t i = 0; i < iterations; ++i) {
    if (get_random_number(&drng_seed, seed, SEED_LEN_BYTES * 8) != 0) {
      fprintf(stderr, "drng seed output failed\n");
      free(pk);
      free(sk);
      free(sn);
      free(seed);
      free(message);
      free(nonce1);
      bench_iteration_stats_free(&iter_stats);
      return 1;
    }
    fill_signature_message(message, message_len, i);

    if (init_random_number(&drng_algorithm, seed, SEED_LEN_BYTES) != 0) {
      fprintf(stderr, "drng algorithm init failed\n");
      free(pk);
      free(sk);
      free(sn);
      free(seed);
      free(message);
      free(nonce1);
      bench_iteration_stats_free(&iter_stats);
      return 1;
    }

    const uint64_t cyc_start_keygen =
        cycles_ok ? bench_read_cycles() : 0u;
    clock_t start = bench_memory_child ? 0 : clock();
    if (sig_keygen(pk, &pk_len_bytes, sk, &sk_len_bytes) != 0) {
      fprintf(stderr, "sig_keygen failed\n");
      free(pk);
      free(sk);
      free(sn);
      free(seed);
      free(message);
      free(nonce1);
      bench_iteration_stats_free(&iter_stats);
      return 1;
    }
    clock_t end = bench_memory_child ? 0 : clock();
    const double keygen_elapsed_s = seconds_since(start, end);
    iter_stats.keygen_ms[i] = 1000.0 * keygen_elapsed_s;
    const uint64_t cyc_end_keygen = cycles_ok ? bench_read_cycles() : 0u;
    if (cycles_ok && bench_cycles_available() && cyc_end_keygen >= cyc_start_keygen) {
      const long double keygen_cycles = (long double)(cyc_end_keygen - cyc_start_keygen);
      iter_stats.keygen_mcyc[i] = keygen_cycles / 1000000.0L;
    }

    const uint64_t cyc_start_sign =
        cycles_ok ? bench_read_cycles() : 0u;
    start = bench_memory_child ? 0 : clock();
    if (sig_sign(sk, sk_len_bytes, message, message_len, sn, &sn_len_bytes) != 0) {
      fprintf(stderr, "sig_sign failed\n");
      free(pk);
      free(sk);
      free(sn);
      free(seed);
      free(message);
      free(nonce1);
      bench_iteration_stats_free(&iter_stats);
      return 1;
    }
    end = bench_memory_child ? 0 : clock();
    const double sign_elapsed_s = seconds_since(start, end);
    iter_stats.sign_ms[i] = 1000.0 * sign_elapsed_s;
    const uint64_t cyc_end_sign = cycles_ok ? bench_read_cycles() : 0u;
    if (cycles_ok && bench_cycles_available() && cyc_end_sign >= cyc_start_sign) {
      const long double sign_cycles = (long double)(cyc_end_sign - cyc_start_sign);
      iter_stats.sign_mcyc[i] = sign_cycles / 1000000.0L;
    }

    const uint64_t cyc_start_verify =
        cycles_ok ? bench_read_cycles() : 0u;
    start = bench_memory_child ? 0 : clock();
    if (sig_verify(pk, pk_len_bytes, sn, sn_len_bytes, message, message_len) != 0) {
      fprintf(stderr, "sig_verify failed\n");
      free(pk);
      free(sk);
      free(sn);
      free(seed);
      free(message);
      free(nonce1);
      bench_iteration_stats_free(&iter_stats);
      return 1;
    }
    end = bench_memory_child ? 0 : clock();
    const double verify_elapsed_s = seconds_since(start, end);
    iter_stats.verify_ms[i] = 1000.0 * verify_elapsed_s;
    const uint64_t cyc_end_verify = cycles_ok ? bench_read_cycles() : 0u;
    if (cycles_ok && bench_cycles_available() && cyc_end_verify >= cyc_start_verify) {
      const long double verify_cycles = (long double)(cyc_end_verify - cyc_start_verify);
      iter_stats.verify_mcyc[i] = verify_cycles / 1000000.0L;
    }

    message_len += message_len_step;
  }

  printf("sm4th_em_d2_128f_loose benchmark (iterations=%zu, mode=%s)\n", iterations,
         bench_memory_child ? "memory" : "speed");
  printf("message length: 56 + %zu*i bytes%s\n", message_len_step,
         message_len_step == 0 ? " (fixed 56B)" : "");
  printf("message content: deterministic ASCII prefix \"Chinith sm4th ublockith vistrutith 56-byte bench msg v1.\"\n");
  /* Instrumented RSS runs never publish their timing samples. */
  if (!bench_memory_child) {
    puts("time source: clock() process CPU time (user + system)");
    printf("measured iterations: %zu; warmup excluded: 0\n", iterations);
    printf("cycle source: %s\n", bench_cycles_source());
    bench_cycles_print_metadata();
    const int have_cycles = bench_cycles_available();
    puts("operation     mean ms/op     mean cycles/op   mean Mcycles/op");
    bench_print_average("keygen", iter_stats.keygen_ms, iter_stats.keygen_mcyc,
                        iterations, have_cycles);
    bench_print_average("sign", iter_stats.sign_ms, iter_stats.sign_mcyc,
                        iterations, have_cycles);
    bench_print_average("verify", iter_stats.verify_ms, iter_stats.verify_mcyc,
                        iterations, have_cycles);
    if (detailed) {
      printf("per-iteration ms/op stats (average / min / median / p90 / max)\n");
      bench_print_double_stats("keygen", iter_stats.keygen_ms, iterations);
      bench_print_double_stats("sign", iter_stats.sign_ms, iterations);
      bench_print_double_stats("verify", iter_stats.verify_ms, iterations);
      if (have_cycles) {
        printf("per-iteration Mcyc/op stats (average / min / median / p90 / max)\n");
        bench_print_long_double_stats("keygen", iter_stats.keygen_mcyc, iterations);
        bench_print_long_double_stats("sign", iter_stats.sign_mcyc, iterations);
        bench_print_long_double_stats("verify", iter_stats.verify_mcyc, iterations);
      }
    }
  }
  printf("pk size: %llu bytes\n", pk_len_bytes);
  printf("sk size: %llu bytes\n", sk_len_bytes);
  printf("sig size: %llu bytes\n", sn_len_bytes);
  if (!bench_memory_child) {
    puts("memory source: separate measurement; use --all or CHINITH_BENCH_MEMORY=1");
  }

  bench_iteration_stats_free(&iter_stats);
  free(pk);
  free(sk);
  free(sn);
  free(seed);
  free(message);
  free(nonce1);
  return 0;
}
