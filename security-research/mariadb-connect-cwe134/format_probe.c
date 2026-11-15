#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

typedef int (*vsnprintf_chk_fn)(char *, size_t, int, size_t,
                                const char *, va_list);
static vsnprintf_chk_fn real_vsnprintf_chk;

static size_t append_text(char *dst, size_t pos, const char *src) {
  while (*src && pos < 1900) dst[pos++] = *src++;
  return pos;
}
static size_t append_hex(char *dst, size_t pos, uintptr_t value) {
  static const char digits[] = "0123456789abcdef";
  char tmp[2 * sizeof(value)];
  size_t n = 0;
  do { tmp[n++] = digits[value & 0xf]; value >>= 4; } while (value && n < sizeof(tmp));
  if (pos < 1900) dst[pos++] = '0';
  if (pos < 1900) dst[pos++] = 'x';
  while (n && pos < 1900) dst[pos++] = tmp[--n];
  return pos;
}
static void emit_map_for(uintptr_t value, unsigned index) {
  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp) return;
  char line[1024];
  while (fgets(line, sizeof(line), fp)) {
    unsigned long lo = 0, hi = 0;
    if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 &&
        value >= lo && value < hi) {
      char out[1200];
      int n = snprintf(out, sizeof(out), "CONNECT_MAP arg%u=%s", index, line);
      if (n > 0) (void)write(STDERR_FILENO, out, (size_t)n);
      if (strstr(line, "[stack]")) {
        int mem = open("/proc/self/mem", O_RDONLY);
        if (mem >= 0) {
          unsigned char bytes[128];
          uintptr_t start = value >= lo + 64 ? value - 64 : lo;
          ssize_t got = pread(mem, bytes, sizeof(bytes), (off_t)start);
          if (got > 0) {
            size_t pos = 0;
            pos = append_text(out, 0, "CONNECT_STACK_DUMP addr=");
            pos = append_hex(out, pos, start);
            pos = append_text(out, pos, " bytes=");
            static const char hx[] = "0123456789abcdef";
            for (ssize_t i = 0; i < got && pos + 2 < sizeof(out); ++i) {
              out[pos++] = hx[bytes[i] >> 4];
              out[pos++] = hx[bytes[i] & 15];
            }
            out[pos++] = '\n';
            (void)write(STDERR_FILENO, out, pos);
          }
          close(mem);
        }
      }
      break;
    }
  }
  fclose(fp);
}

__attribute__((constructor))
static void init_real_vsnprintf_chk(void) {
  real_vsnprintf_chk = (vsnprintf_chk_fn)dlsym(RTLD_NEXT, "__vsnprintf_chk");
}

int __snprintf_chk(char *dst, size_t maxlen, int flag, size_t objsize,
                   const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  if (format && strncmp(format, "PROBE_", 6) == 0) {
    va_list scan;
    uintptr_t values[12] = {0};
    char line[2048];
    size_t pos = 0;
    va_copy(scan, ap);
    pos = append_text(line, pos, "CONNECT_FMT_PROBE");
    for (unsigned i = 0; i < 12; ++i) {
      values[i] = va_arg(scan, uintptr_t);
      pos = append_text(line, pos, " arg");
      char number[24];
      int n = snprintf(number, sizeof(number), "%u=", i + 1);
      if (n > 0) pos = append_text(line, pos, number);
      pos = append_hex(line, pos, values[i]);
    }
    if (pos < sizeof(line)) line[pos++] = '\n';
    (void)write(STDERR_FILENO, line, pos);
    va_end(scan);
    for (unsigned i = 0; i < 12; ++i)
      if (values[i]) emit_map_for(values[i], i + 1);
    int result = vsnprintf(dst, maxlen, format, ap);
    va_end(ap);
    return result;
  }
  if (real_vsnprintf_chk) {
    int result = real_vsnprintf_chk(dst, maxlen, flag, objsize, format, ap);
    va_end(ap);
    return result;
  }
  int result = vsnprintf(dst, maxlen, format, ap);
  va_end(ap);
  return result;
}
