/* Retain the benchmark statistics used by these instance entry points. */
#ifndef CHINITH_IMPLEMENTATIONS_BENCH_CYCLES_H
#define CHINITH_IMPLEMENTATIONS_BENCH_CYCLES_H

#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
extern long syscall(long number, ...);
#endif

/* Report direct, pinned user CPU cycles only; invalidate rather than estimate. */
typedef struct {
  int initialized;
  int perf_fd;
  int use_perf;
  int have_read;
  int error_number;
  const char* source;
  const char* error;
  uint64_t last_value;
  uint64_t time_enabled;
  uint64_t time_running;
} bench_cycles_state_t;

static bench_cycles_state_t bench_cycles_state = {
    0, -1, 0, 0, 0, "unavailable", "Linux perf_event CPU_CYCLES unavailable", 0, 0, 0};

static inline void bench_cycles_invalidate(const char* error, int error_number) {
  bench_cycles_state.use_perf = 0;
  bench_cycles_state.source = "unavailable";
  bench_cycles_state.error = error;
  bench_cycles_state.error_number = error_number;
#if defined(__linux__)
  if (bench_cycles_state.perf_fd >= 0) {
    close(bench_cycles_state.perf_fd);
    bench_cycles_state.perf_fd = -1;
  }
#endif
}

static void bench_cycles_init(void) {
  if (bench_cycles_state.initialized) {
    return;
  }
  bench_cycles_state.initialized = 1;

#if defined(__linux__)
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_HARDWARE;
  attr.size = sizeof(attr);
  attr.config = PERF_COUNT_HW_CPU_CYCLES;
  attr.disabled = 1;
  attr.pinned = 1;
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;

  bench_cycles_state.perf_fd =
      (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
  if (bench_cycles_state.perf_fd < 0) {
    bench_cycles_invalidate("perf_event_open failed", errno);
    return;
  }
  if (ioctl(bench_cycles_state.perf_fd, PERF_EVENT_IOC_RESET, 0) != 0) {
    bench_cycles_invalidate("PERF_EVENT_IOC_RESET failed", errno);
    return;
  }
  if (ioctl(bench_cycles_state.perf_fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
    bench_cycles_invalidate("PERF_EVENT_IOC_ENABLE failed", errno);
    return;
  }
  bench_cycles_state.use_perf = 1;
  bench_cycles_state.source = "perf_event cpu-cycles (user)";
  bench_cycles_state.error = "none";
#endif
}

static inline int bench_cycles_available(void) {
  bench_cycles_init();
  return bench_cycles_state.use_perf;
}

static inline const char* bench_cycles_source(void) {
  bench_cycles_init();
  return bench_cycles_state.source;
}

static inline uint64_t bench_read_cycles(void) {
  bench_cycles_init();
#if defined(__linux__)
  if (bench_cycles_state.use_perf) {
    uint64_t sample[3]; /* value, time_enabled, time_running (nanoseconds) */
    const ssize_t nread = read(bench_cycles_state.perf_fd, sample, sizeof(sample));
    if (nread != (ssize_t)sizeof(sample)) {
      bench_cycles_invalidate("perf read failed or incomplete", nread < 0 ? errno : 0);
      return UINT64_MAX;
    }
    const int regressed = bench_cycles_state.have_read &&
        (sample[0] < bench_cycles_state.last_value ||
         sample[1] < bench_cycles_state.time_enabled ||
         sample[2] < bench_cycles_state.time_running);
    bench_cycles_state.have_read = 1;
    bench_cycles_state.last_value = sample[0];
    bench_cycles_state.time_enabled = sample[1];
    bench_cycles_state.time_running = sample[2];
    if (sample[2] == 0 || sample[1] != sample[2]) {
      bench_cycles_invalidate("perf event not continuously running (no scaling)", 0);
      return UINT64_MAX;
    }
    if (regressed) {
      bench_cycles_invalidate("perf counter or timing metadata regressed", 0);
      return UINT64_MAX;
    }
    return sample[0];
  }
#endif
  return UINT64_MAX;
}

static inline void bench_cycles_print_metadata(void) {
  bench_cycles_init();
  printf("cycle pinned: 1\n");
  printf("cycle valid: %s\n", bench_cycles_state.use_perf ? "yes" : "no");
  if (bench_cycles_state.have_read) {
    printf("cycle time enabled (ns): %" PRIu64 "\n", bench_cycles_state.time_enabled);
    printf("cycle time running (ns): %" PRIu64 "\n", bench_cycles_state.time_running);
  } else {
    printf("cycle time enabled (ns): N/A\n");
    printf("cycle time running (ns): N/A\n");
  }
  printf("cycle error: %s", bench_cycles_state.error);
  if (bench_cycles_state.error_number != 0) {
    printf(" (errno=%d: %s)", bench_cycles_state.error_number,
           strerror(bench_cycles_state.error_number));
  }
  printf("\n");
}

typedef struct {
  double* keygen_ms;
  double* sign_ms;
  double* verify_ms;
  long double* keygen_mcyc;
  long double* sign_mcyc;
  long double* verify_mcyc;
} bench_iteration_stats_t;

static void bench_iteration_stats_free(bench_iteration_stats_t* stats) {
  if (!stats) {
    return;
  }
  free(stats->keygen_ms);
  free(stats->sign_ms);
  free(stats->verify_ms);
  free(stats->keygen_mcyc);
  free(stats->sign_mcyc);
  free(stats->verify_mcyc);
  memset(stats, 0, sizeof(*stats));
}

static int bench_iteration_stats_init(bench_iteration_stats_t* stats, size_t count) {
  if (!stats) {
    return -1;
  }
  memset(stats, 0, sizeof(*stats));
  stats->keygen_ms = (double*)calloc(count, sizeof(*stats->keygen_ms));
  stats->sign_ms = (double*)calloc(count, sizeof(*stats->sign_ms));
  stats->verify_ms = (double*)calloc(count, sizeof(*stats->verify_ms));
  stats->keygen_mcyc = (long double*)calloc(count, sizeof(*stats->keygen_mcyc));
  stats->sign_mcyc = (long double*)calloc(count, sizeof(*stats->sign_mcyc));
  stats->verify_mcyc = (long double*)calloc(count, sizeof(*stats->verify_mcyc));
  if (!stats->keygen_ms || !stats->sign_ms || !stats->verify_ms ||
      !stats->keygen_mcyc || !stats->sign_mcyc || !stats->verify_mcyc) {
    bench_iteration_stats_free(stats);
    return -1;
  }
  return 0;
}

static int bench_compare_double(const void* a, const void* b) {
  const double lhs = *(const double*)a;
  const double rhs = *(const double*)b;
  return (lhs > rhs) - (lhs < rhs);
}

static int bench_compare_long_double(const void* a, const void* b) {
  const long double lhs = *(const long double*)a;
  const long double rhs = *(const long double*)b;
  return (lhs > rhs) - (lhs < rhs);
}

static size_t bench_p90_index(size_t count) {
  size_t idx = (count * 9u + 9u) / 10u;
  if (idx == 0) {
    return 0;
  }
  idx--;
  return idx < count ? idx : count - 1u;
}

static int bench_double_stats(const double* samples, size_t count, double* min,
                              double* median, double* p90, double* max) {
  double* sorted = (double*)malloc(count * sizeof(*sorted));
  if (!sorted) {
    return -1;
  }
  memcpy(sorted, samples, count * sizeof(*sorted));
  qsort(sorted, count, sizeof(*sorted), bench_compare_double);
  *min = sorted[0];
  *max = sorted[count - 1u];
  if (count & 1u) {
    *median = sorted[count / 2u];
  } else {
    *median = (sorted[count / 2u - 1u] + sorted[count / 2u]) / 2.0;
  }
  *p90 = sorted[bench_p90_index(count)];
  free(sorted);
  return 0;
}

static int bench_long_double_stats(const long double* samples, size_t count,
                                   long double* min, long double* median,
                                   long double* p90, long double* max) {
  long double* sorted = (long double*)malloc(count * sizeof(*sorted));
  if (!sorted) {
    return -1;
  }
  memcpy(sorted, samples, count * sizeof(*sorted));
  qsort(sorted, count, sizeof(*sorted), bench_compare_long_double);
  *min = sorted[0];
  *max = sorted[count - 1u];
  if (count & 1u) {
    *median = sorted[count / 2u];
  } else {
    *median = (sorted[count / 2u - 1u] + sorted[count / 2u]) / 2.0L;
  }
  *p90 = sorted[bench_p90_index(count)];
  free(sorted);
  return 0;
}

static void bench_print_double_stats(const char* label, const double* samples,
                                     size_t count) {
  double average = 0.0;
  double min = 0.0;
  double median = 0.0;
  double p90 = 0.0;
  double max = 0.0;
  if (bench_double_stats(samples, count, &min, &median, &p90, &max) != 0) {
    printf("%-6s: N/A\n", label);
    return;
  }
  for (size_t i = 0; i != count; ++i) {
    average += samples[i];
  }
  average /= (double)count;
  printf("%-6s: %.6f / %.6f / %.6f / %.6f / %.6f\n", label,
         average, min, median, p90, max);
}

static void bench_print_long_double_stats(const char* label,
                                          const long double* samples,
                                          size_t count) {
  long double average = 0.0L;
  long double min = 0.0L;
  long double median = 0.0L;
  long double p90 = 0.0L;
  long double max = 0.0L;
  if (bench_long_double_stats(samples, count, &min, &median, &p90, &max) != 0) {
    printf("%-6s: N/A\n", label);
    return;
  }
  for (size_t i = 0; i != count; ++i) {
    average += samples[i];
  }
  average /= (long double)count;
  printf("%-6s: %.6Lf / %.6Lf / %.6Lf / %.6Lf / %.6Lf\n", label,
         average, min, median, p90, max);
}

#endif
