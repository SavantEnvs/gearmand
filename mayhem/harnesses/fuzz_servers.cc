// libgearman server-list parser: "host[:port],host[:port],[v6]:port" lists given to
// gearman_client_add_servers / gearman_worker_add_servers. No
// connection is made: adding a server only parses and records it.
#include <libgearman/gearman.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string s(reinterpret_cast<const char *>(data), size);  // NUL-terminated copy
  gearman_client_st *c = gearman_client_create(nullptr);
  gearman_client_add_servers(c, s.c_str());
  gearman_client_free(c);
  gearman_worker_st *w = gearman_worker_create(nullptr);
  gearman_worker_add_servers(w, s.c_str());
  gearman_worker_free(w);
  return 0;
}
