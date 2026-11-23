// gearmand's command line + configuration file parsing (gearmand/gearmand.cc main). The input is a
// gearmand config file (--config-file=FILE): main() tokenizes it and parses the tokens with the
// full gearmand option set (server options plus every protocol/queue plugin's options), then
// validates them (verbose level, hashtable buckets, job retries, ...).
//
// gearmand/gearmand.cc is compiled with main renamed to gearmand_main (build.sh). Per input the
// harness writes the bytes to a scratch file and runs
//   gearmand --check-args --config-file=<file>
// which returns right after option parsing and validation, before the server is created.
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

int gearmand_main(int argc, char *argv[]);

static std::string path;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  // Scratch config file: a unique file under $TMPDIR (fallback /tmp), created once with mkstemp()
  // and rewritten per input.
  const char *tmp = getenv("TMPDIR");
  path = std::string(tmp != nullptr && *tmp != '\0' ? tmp : "/tmp") + "/fuzz_config.XXXXXX";
  int fd = mkstemp(&path[0]);
  if (fd < 0) __builtin_trap();
  close(fd);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FILE *f = fopen(path.c_str(), "wb");
  if (f == nullptr) return 0;
  fwrite(data, 1, size, f);
  fclose(f);
  std::string cfg = "--config-file=" + path;
  char a0[] = "gearmand", a1[] = "--check-args";
  char *argv[] = {a0, a1, &cfg[0], nullptr};
  (void)gearmand_main(3, argv);
  return 0;
}
