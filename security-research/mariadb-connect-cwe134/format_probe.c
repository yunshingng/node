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
static void emit_map_and_memory(uintptr_t value, unsigned index) {
  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp) return;
  char line[1024];
  int writable = 0;
  unsigned long lo = 0, hi = 0;
  while (fgets(line, sizeof(line), fp)) {
    unsigned long a = 0, b = 0;
    if (sscanf(line, "%lx-%lx", &a, &b) == 2 && value >= a && value < b) {
      lo = a; hi = b; char *perms = strchr(line, ' '); writable = perms && perms[2] == 'w';
      char out[1200];
      int n = snprintf(out, sizeof(out), "CONNECT_MAP arg%u=%s", index, line);
      if (n > 0) (void)write(STDERR_FILENO, out, (size_t)n);
      break;
    }
  }
  fclose(fp);
  if (!writable) return;
  unsigned char bytes[96];
  uintptr_t start = value >= lo + 32 ? value - 32 : lo;
  size_t want = sizeof(bytes);
  if (start + want > hi) want = hi - start;
  memcpy(bytes, (const void *)start, want);
  ssize_t got = (ssize_t)want;
  if (got > 0) {
    char out[1200];
    size_t pos = 0;
    pos = append_text(out, pos, "CONNECT_MEM arg");
    char number[24];
    int n = snprintf(number, sizeof(number), "%u addr=", index);
    if (n > 0) pos = append_text(out, pos, number);
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
    for (unsigned i = 0; i < 12; ++i) {
      if (!values[i]) continue;
      emit_map_and_memory(values[i], i + 1);
      if (i == 4) {
        uintptr_t first_word = *(const uintptr_t *)values[i];
        Dl_info info;
        if (dladdr((void *)first_word, &info)) {
          char sym[1024];
          int n = snprintf(sym, sizeof(sym),
                           "CONNECT_OBJECT arg5=%p first_word=%p image=%s symbol=%s\n",
                           (void *)values[i], (void *)first_word,
                           info.dli_fname ? info.dli_fname : "?",
                           info.dli_sname ? info.dli_sname : "?");
          if (n > 0) (void)write(STDERR_FILENO, sym, (size_t)n);
        }
      }
    }
    int result = vsnprintf(dst, maxlen, format, ap);
    for (unsigned i = 0; i < 12; ++i)
      if (values[i]) emit_map_and_memory(values[i], i + 21);
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
