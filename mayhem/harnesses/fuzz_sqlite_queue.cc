// gearmand persistent-queue replay from a sqlite database file (--queue-type=libsqlite3
// --libsqlite3-db=FILE). At startup gearmand opens the file, checks/creates the gearman_queue
// table, then replays every stored row (unique, function, priority, data, when) back into the job
// server. The input is that database file.
//
// One gearmand instance is created at init with the builtin (no-op) queue, as gearmand.cc main
// does before it starts; the library allows only one instance per process. Per input the harness
// writes the bytes to its scratch database file (mkstemp under $TMPDIR), opens it with the libsqlite3 queue plugin's Instance
// (init() = open + schema check/create + prepare), replays it into the server exactly as
// gearmand_run() does at startup (state.queue_startup set), then frees every replayed job and
// function record so the next input starts from an empty server (the job-handle counter still
// advances; only the digits of the next "H:fuzz:N" handle change).
#include "gear_config.h"
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "libgearman-server/common.h"
#include "libgearman-server/gearmand.h"
#include "libgearman-server/plugins.h"
#include <boost/program_options.hpp>
#include "libgearman-server/plugins/queue/sqlite/instance.hpp"
#include "libgearman-server/queue.hpp"

static gearmand_st *g;
static std::string db_path;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  // Registers the queue plugins (builtin among them), as gearmand.cc main does.
  boost::program_options::options_description all("gearmand");
  gearmand::plugins::initialize(all);
  gearmand_config_st *config = gearmand_config_create();
  g = gearmand_create(config, "127.0.0.1", 0, 32, 0, "H:fuzz", 0, nullptr, nullptr,
                      GEARMAND_VERBOSE_FATAL, false, false, 991);
  gearmand_config_free(config);
  if (g == nullptr) __builtin_trap();
  if (gearmand::queue::initialize(g, "builtin") != GEARMAND_SUCCESS) __builtin_trap();
  // Scratch database: a unique file under $TMPDIR (fallback /tmp), created once with mkstemp()
  // and rewritten per input.
  const char *tmp = getenv("TMPDIR");
  std::string tmpl = std::string(tmp != nullptr && *tmp != '\0' ? tmp : "/tmp") +
                     "/fuzz_sqlite_queue.XXXXXX";
  int fd = mkstemp(&tmpl[0]);
  if (fd < 0) __builtin_trap();
  close(fd);
  db_path = tmpl;
  return 0;
}

// Frees every job, then every function record, the way gearman_server_free() does at shutdown
// (without saving them to a queue). The harness has no worker or client connections, so no job is
// running or has clients; gearman_server_job_free() unlinks a job from the job and unique hashes
// (not from its function's queue, which goes with the function), and gearman_server_function_free()
// also deletes the function's epoch wakeup timer. Afterwards both tables are empty, as at startup.
// (gearman_server_job_cancel() would only mark the jobs ignored and leave them queued.)
static void free_jobs_and_functions(gearman_server_st &server) {
  for (uint32_t b = 0; b < server.hashtable_buckets; b++)
    while (server.job_hash[b] != nullptr) gearman_server_job_free(server.job_hash[b]);
  for (uint32_t k = 0; k < GEARMAND_DEFAULT_HASH_SIZE; k++)
    while (server.function_hash[k] != nullptr)
      gearman_server_function_free(&server, server.function_hash[k]);
}

static void remove_side_files() {
  unlink((db_path + "-journal").c_str());
  unlink((db_path + "-wal").c_str());
  unlink((db_path + "-shm").c_str());
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  remove_side_files();
  FILE *f = fopen(db_path.c_str(), "wb");
  if (f == nullptr) return 0;
  fwrite(data, 1, size, f);
  fclose(f);

  gearman_server_st &server = g->server;
  {
    gearmand::queue::Instance inst(db_path, "gearman_queue");
    if (inst.init() == GEARMAND_SUCCESS) {
      server.state.queue_startup = true;
      (void)inst.replay(&server);
      server.state.queue_startup = false;
    }
  }

  free_jobs_and_functions(server);

  remove_side_files();
  return 0;
}
