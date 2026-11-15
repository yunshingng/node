#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

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

__attribute__((constructor))
static void init_real_vsnprintf_chk(void) {
  real_vsnprintf_chk = (vsnprintf_chk_fn)dlsym(RTLD_NEXT, "__vsnprintf_chk");
}

/*
 * Probe only a filename deliberately prefixed with PROBE_. For that one
 * controlled test string, log the raw variadic slots and call plain vsnprintf
 * so the fortified %n guard does not mask the argument-layout observation.
 * All ordinary strings retain the system __vsnprintf_chk behaviour.
 */
int __snprintf_chk(char *dst, size_t maxlen, int flag, size_t objsize,
                   const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  if (format && strncmp(format, "PROBE_", 6) == 0) {
    va_list scan;
    char line[2048];
    size_t pos = 0;
    va_copy(scan, ap);
    pos = append_text(line, pos, "CONNECT_FMT_PROBE");
    for (unsigned i = 1; i <= 12; ++i) {
      uintptr_t value = va_arg(scan, uintptr_t);
      pos = append_text(line, pos, " arg");
      pos = append_hex(line, pos, i);
      if (pos < sizeof(line)) line[pos++] = '=';
      pos = append_hex(line, pos, value);
    }
    if (pos < sizeof(line)) line[pos++] = '\n';
    (void)write(STDERR_FILENO, line, pos);
    va_end(scan);
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
