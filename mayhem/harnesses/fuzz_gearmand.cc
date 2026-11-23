// gearmand server: the Gear binary protocol + text admin commands (Gear plugin) and the HTTP
// protocol plugin, driven over loopback TCP exactly as clients reach a running gearmand.
//
// One in-process server is started at init (gearmand_create + builtin queue + Gear + HTTP
// plugins, as gearmand/gearmand.cc main does, then gearmand_run in a thread). It cannot be
// recreated per input: gearmand_free() leaves the library's global instance pointer dangling and
// gearmand_create() refuses a second instance. So after every input, with all of the input's
// connections closed, the harness puts the server back over the text admin protocol:
//   - "show jobs" lists the jobs and "cancel job" cancels each one; a cancelled job stays queued
//     until a worker asks for it, so the harness then connects as a worker for that function
//     (CAN_DO + GRAB_JOB) and the server frees the cancelled jobs;
//   - "status" lists the registered functions and "drop function" removes each one, which also
//     drops any per-function queue limit an input set with "maxqueue" or a function it registered
//     with "create function" (repeated until "status" lists none the admin protocol can name).
// What still carries over, on purpose:
//   - the job-handle counter (only the digits of the next "H:fuzz:N" handle change);
//   - a cancelled SUBMIT_JOB_EPOCH job scheduled in the future: no worker can take it before its
//     time, so it and its function stay until then (cancelled, so it never runs);
//   - a function record whose name the text admin protocol cannot address (it is empty or
//     contains a space or a newline). Its jobs are still cancelled and drained, so it has no jobs
//     and no workers, and its queue limits are the defaults, because "maxqueue" cannot address it
//     either; the only trace is its line in a later "status"/"workers" reply.
//
// Input layout: byte 0 selects the routing, the rest is split on the separator "|CONN|" into up
// to 3 connection payloads. Bit i (i = 0..2) of byte 0 routes connection i to the HTTP port
// instead of the Gear port. All connections are opened first, then each payload is sent in
// order (so e.g. a worker on one connection and a client on another interact), the write side is
// closed and the replies are read until the server hangs up.
#include "gear_config.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>
#include <vector>

#include <boost/program_options.hpp>
#include "libgearman-server/gearmand.h"
#include "libgearman-server/plugins.h"
#include "libgearman-server/queue.hpp"

static gearmand::protocol::Gear *gear;
static gearmand::protocol::HTTP *http;
static in_port_t gear_port, http_port;

static in_port_t free_port() {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, (sockaddr *)&a, sizeof(a)) != 0) __builtin_trap();
  socklen_t l = sizeof(a);
  getsockname(fd, (sockaddr *)&a, &l);
  close(fd);
  return ntohs(a.sin_port);
}

static void *run(void *g) {
  gearmand_run(static_cast<gearmand_st *>(g));
  return nullptr;
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  gear_port = free_port();
  do { http_port = free_port(); } while (http_port == gear_port);
  boost::program_options::options_description all("gearmand");
  // gearmand_port_add() memcpy()s NI_MAXSERV (32) bytes out of the plugin's short std::string
  // port (an upstream over-read, libgearman-server/gearmand.cc). HTTP's _port is its last member,
  // so on the heap that read runs past the object on every start; give it padded static storage so
  // the setup itself does not abort every input. Gear's _port is followed by other members.
  alignas(gearmand::protocol::HTTP) static char http_storage[sizeof(gearmand::protocol::HTTP) + 64];
  http = new (http_storage) gearmand::protocol::HTTP;
  all.add(http->command_line_options());
  gear = new gearmand::protocol::Gear;
  all.add(gear->command_line_options());
  gearmand::plugins::initialize(all);
  std::string p = "--port=" + std::to_string(gear_port);
  std::string hp = "--http-port=" + std::to_string(http_port);
  const char *argv[] = {"gearmand", p.c_str(), hp.c_str()};
  boost::program_options::variables_map vm;
  boost::program_options::store(boost::program_options::parse_command_line(3, argv, all), vm);
  boost::program_options::notify(vm);

  gearmand_config_st *config = gearmand_config_create();
  gearmand_st *g = gearmand_create(config, "127.0.0.1", 0, 32, 0, "H:fuzz", 0, nullptr, nullptr,
                                   GEARMAND_VERBOSE_FATAL, false, false, 991);
  gearmand_config_free(config);
  if (g == nullptr) __builtin_trap();
  if (gearmand::queue::initialize(g, "builtin") != GEARMAND_SUCCESS) __builtin_trap();
  if (gear->start(g) != GEARMAND_SUCCESS) __builtin_trap();
  if (http->start(g) != GEARMAND_SUCCESS) __builtin_trap();
  pthread_t th;
  pthread_create(&th, nullptr, run, g);
  pthread_detach(th);
  return 0;
}

static int connect_to(in_port_t port) {
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons(port);
  for (;;) {  // the server thread may not be listening yet
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(fd, (sockaddr *)&a, sizeof(a)) == 0) return fd;
    close(fd);
    sched_yield();
  }
}

static void send_all(int fd, const std::string &c) {
  size_t off = 0;
  while (off < c.size()) {
    ssize_t n = send(fd, c.data() + off, c.size() - off, MSG_NOSIGNAL);
    if (n <= 0) return;
    off += (size_t)n;
  }
}

static std::vector<std::string> lines_of(const std::string &out) {
  std::vector<std::string> v;
  size_t pos = 0;
  while (pos < out.size()) {
    size_t eol = out.find('\n', pos);
    if (eol == std::string::npos) break;
    v.push_back(out.substr(pos, eol - pos));
    pos = eol + 1;
  }
  return v;
}

// Send cmds (ending in a listing command) on the admin connection and read until the "." line
// that ends the listing. The server closes a connection on EOF without answering, so the reply
// is read before the write side is shut. Earlier one-line replies ("OK", "ERR ...") come first.
static std::string admin(int fd, const std::string &cmds) {
  send_all(fd, cmds);
  std::string out;
  char buf[4096];
  while (!(out == ".\n" || (out.size() >= 3 && out.compare(out.size() - 3, 3, "\n.\n") == 0))) {
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    out.append(buf, (size_t)n);
  }
  return out;
}

static std::string packet(uint32_t cmd, const std::string &arg) {
  std::string p("\0REQ", 4);
  for (uint32_t v : {cmd, (uint32_t)arg.size()})
    for (int sh = 24; sh >= 0; sh -= 8) p += char((v >> sh) & 0xff);
  return p + arg;
}

static bool recv_exact(int fd, std::string &out, size_t n) {
  out.clear();
  char buf[4096];
  while (out.size() < n) {
    ssize_t r = recv(fd, buf, std::min(sizeof(buf), n - out.size()), 0);
    if (r <= 0) return false;
    out.append(buf, (size_t)r);
  }
  return true;
}

// A cancelled job is only marked "ignore" and stays on its function's queue until a worker asks
// for work: GRAB_JOB then frees it (gearman_server_job_take). Act as that worker for one function
// A job still handed out (JOB_ASSIGN) is failed back with WORK_FAIL, which ends it.
static void drain(const std::string &name) {
  enum { CAN_DO = 1, GRAB_JOB = 9, NO_JOB = 10, JOB_ASSIGN = 11, WORK_FAIL = 14 };
  int fd = connect_to(gear_port);
  send_all(fd, packet(CAN_DO, name));
  std::string hdr, body;
  for (int i = 0; i < 1024; i++) {
    send_all(fd, packet(GRAB_JOB, ""));
    if (!recv_exact(fd, hdr, 12)) break;
    uint32_t cmd = 0, len = 0;
    for (int k = 0; k < 4; k++) cmd = cmd << 8 | (uint8_t)hdr[4 + k];
    for (int k = 0; k < 4; k++) len = len << 8 | (uint8_t)hdr[8 + k];
    if (!recv_exact(fd, body, len)) break;
    if (cmd != JOB_ASSIGN) break;  // NO_JOB: every ignored job ahead of it was freed
    send_all(fd, packet(WORK_FAIL, body.substr(0, body.find('\0'))));
  }
  shutdown(fd, SHUT_WR);
  char buf[4096];
  while (recv(fd, buf, sizeof(buf), 0) > 0) {}
  close(fd);
}

// Undo everything an input left on the server: jobs, then functions and their queue limits.
static void reset_server() {
  // "show jobs" lines are "<handle>\t<retries>\t<ignore>\t<queued>"; "status" lines are
  // "<name>\t<total>\t<running>\t<workers>". Each pass cancels the jobs not yet cancelled,
  // drains the cancelled ones of an idle function with a worker, and drops a function once it
  // has no jobs and no workers (so the harness never frees a function that still owns jobs).
  // While the server is still releasing a closed worker connection its counters are not zero yet,
  // so list again. A name with a newline spans several "status" lines and is joined back for the
  // worker; it and a name with a space cannot be given to "drop function" (a text command ends at
  // the newline, its arguments split on spaces); "\r\n" ends each command so a name ending in '\r' survives the server's strip of
  // one trailing '\r'. Bounded: the loop ends on the first pass that changes nothing.
  int fd = connect_to(gear_port);
  std::string cmds, last;
  for (int pass = 0; pass < 64; pass++) {
    std::string cancels;
    for (const std::string &line : lines_of(admin(fd, cmds + "show jobs\n"))) {
      size_t t1 = line.find('\t');
      size_t t2 = t1 == std::string::npos ? t1 : line.find('\t', t1 + 1);
      if (t1 == std::string::npos || t1 == 0 || t2 == std::string::npos) continue;
      if (line.compare(t2, 3, "\t0\t") == 0)  // not cancelled yet
        cancels += "cancel job " + line.substr(0, t1) + "\r\n";
    }
    if (!cancels.empty()) admin(fd, cancels + "show jobs\n");  // reply lines stay out of "status"
    std::string st = admin(fd, "status\n");
    cmds.clear();
    bool busy = false;
    std::string head;  // the lines so far of a name with a newline in it
    for (const std::string &line : lines_of(st)) {
      size_t t3 = line.rfind('\t');
      size_t t2 = t3 == std::string::npos || t3 == 0 ? std::string::npos : line.rfind('\t', t3 - 1);
      size_t t1 = t2 == std::string::npos || t2 == 0 ? std::string::npos : line.rfind('\t', t2 - 1);
      if (t1 == std::string::npos) {
        head += line + "\n";
        continue;
      }
      std::string name = head + line.substr(0, t1);
      head.clear();
      if (name.empty()) continue;
      if (line.compare(t2, std::string::npos, "\t0\t0") != 0) {
        busy = true;  // running jobs or workers: a closed connection not released yet
      } else if (line.compare(t1, t2 - t1, "\t0") != 0) {
        drain(name);
      } else if (name.find_first_of(" \n") == std::string::npos) {
        cmds += "drop function " + name + "\r\n";
      }
    }
    if (cancels.empty() && cmds.empty() && !busy && (st == ".\n" || st == last)) break;
    if (busy) sched_yield();
    last = st;
  }
  admin(fd, cmds + "status\n");
  shutdown(fd, SHUT_WR);
  char buf[4096];
  while (recv(fd, buf, sizeof(buf), 0) > 0) {}
  close(fd);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  const uint8_t route = data[0];
  std::string rest(reinterpret_cast<const char *>(data + 1), size - 1);
  std::vector<std::string> chunks;
  static const std::string sep = "|CONN|";
  size_t pos = 0;
  while (chunks.size() < 2) {
    size_t n = rest.find(sep, pos);
    if (n == std::string::npos) break;
    chunks.push_back(rest.substr(pos, n - pos));
    pos = n + sep.size();
  }
  chunks.push_back(rest.substr(pos));

  std::vector<int> fds;
  for (size_t i = 0; i < chunks.size(); i++)
    fds.push_back(connect_to((route >> i) & 1 ? http_port : gear_port));
  for (size_t i = 0; i < chunks.size(); i++) {
    send_all(fds[i], chunks[i]);
  }
  for (int fd : fds) shutdown(fd, SHUT_WR);
  char buf[4096];
  for (int fd : fds) {
    while (recv(fd, buf, sizeof(buf), 0) > 0) {}
    close(fd);
  }

  reset_server();
  return 0;
}
