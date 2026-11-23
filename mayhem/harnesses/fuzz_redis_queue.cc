// gearmand persistent-queue replay from a redis server (--queue-type=redis). At startup gearmand
// connects to redis and replays every stored job: SCAN over the key prefix, then HGETALL (or the
// legacy TYPE/GET fallback) per key, decoding the data/priority/function/unique fields. The input
// is the byte stream the redis server sends back (RESP replies), i.e. what a hostile or corrupted
// redis can make gearmand parse.
//
// The harness plays the redis server on a loopback socket. One gearmand instance is created at init
// (the library allows one per process) with the plugins registered and --redis-server/--redis-port
// pointing at the harness's listener. Per input: the redis queue plugin is initialized (it connects;
// the connect completes from the listen backlog), the harness accepts that connection, writes the
// input as the server's reply stream and half-closes it, then gearman_server_queue_replay() runs
// exactly as gearmand_run() does at startup. Afterwards the queue is switched back to the builtin
// one, every replayed job and function record is freed, and the next input frees the redis
// connection before it makes its own, so inputs do not carry state over (the job-handle counter
// still advances; only the digits of the next "H:fuzz:N" handle change).
#include "gear_config.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <string>

#include <boost/program_options.hpp>
#include <hiredis/hiredis.h>
#include "libgearman-server/common.h"
#include "libgearman-server/gearmand.h"
#include "libgearman-server/plugins.h"
#include "libgearman-server/plugins/queue/redis/queue.h"
#include "libgearman-server/queue.hpp"

static gearmand_st *g;
static int listen_fd = -1;
static gearmand::plugins::queue::Hiredis *hiredis;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(listen_fd, (sockaddr *)&a, sizeof(a)) != 0 || listen(listen_fd, 64) != 0)
    __builtin_trap();
  socklen_t l = sizeof(a);
  getsockname(listen_fd, (sockaddr *)&a, &l);
  fcntl(listen_fd, F_SETFL, fcntl(listen_fd, F_GETFL) | O_NONBLOCK);

  // Register the queue plugins and set the redis plugin's options the way gearmand.cc main does.
  boost::program_options::options_description all("gearmand");
  gearmand::plugins::initialize(all);
  std::string port = "--redis-port=" + std::to_string(ntohs(a.sin_port));
  const char *argv[] = {"gearmand", "--redis-server=127.0.0.1", port.c_str()};
  boost::program_options::variables_map vm;
  boost::program_options::store(boost::program_options::parse_command_line(3, argv, all), vm);
  boost::program_options::notify(vm);

  gearmand_config_st *config = gearmand_config_create();
  g = gearmand_create(config, "127.0.0.1", 0, 32, 0, "H:fuzz", 0, nullptr, nullptr,
                      GEARMAND_VERBOSE_FATAL, false, false, 991);
  gearmand_config_free(config);
  if (g == nullptr) __builtin_trap();
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

// Newest pending connection on the listener (connections are queued FIFO); older ones — e.g. a
// plugin reconnect attempt from the previous input — are closed.
static int accept_newest() {
  int fd = -1;
  for (;;) {
    int c = accept(listen_fd, nullptr, nullptr);
    if (c < 0) break;
    if (fd >= 0) close(fd);
    fd = c;
  }
  return fd;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 32768) return 0;  // stays within the loopback socket buffer: written before replay
  gearman_server_st &server = g->server;

  if (hiredis != nullptr) {  // free the previous input's connection; initialize() makes a new one
    redisContext *c = hiredis->redis();
    if (c != nullptr) redisFree(c);
  }
  if (gearmand::queue::initialize(g, "redis") != GEARMAND_SUCCESS) {
    hiredis = nullptr;
    close(accept_newest());
    return 0;
  }
  hiredis = static_cast<gearmand::plugins::queue::Hiredis *>(gearman_server_queue_context(&server));

  int fd = accept_newest();
  if (fd >= 0) {
    size_t off = 0;
    while (off < size) {
      ssize_t n = send(fd, data + off, size - off, MSG_NOSIGNAL);
      if (n <= 0) break;
      off += (size_t)n;
    }
    shutdown(fd, SHUT_WR);
    (void)gearman_server_queue_replay(server);
    close(fd);
  }

  // Back to the builtin queue, so nothing between inputs talks to the closed redis connection.
  if (gearmand::queue::initialize(g, "builtin") != GEARMAND_SUCCESS) __builtin_trap();
  free_jobs_and_functions(server);
  return 0;
}
