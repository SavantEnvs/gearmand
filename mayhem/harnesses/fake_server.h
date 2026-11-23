// A one-shot fake Gearman server on loopback used by the libgearman client/worker harnesses:
// for each input, the first connection the library opens receives the fuzz bytes (the "server
// replies"), then the write side is closed so the library always sees EOF and returns. Any later
// connection in the same input (a library reconnect) is closed immediately. The thread also
// drains whatever the library sends so it never blocks on a full socket buffer.
#pragma once
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <vector>

namespace fake {

static int listen_fd = -1;
static in_port_t port = 0;

static void start() {
  listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = 0;
  if (bind(listen_fd, (sockaddr *)&a, sizeof(a)) != 0 || listen(listen_fd, 16) != 0) __builtin_trap();
  socklen_t l = sizeof(a);
  getsockname(listen_fd, (sockaddr *)&a, &l);
  port = ntohs(a.sin_port);
}

struct Session {
  std::vector<uint8_t> data;
  pthread_t th;
  volatile bool stop = false;
};

static void drain_close(int fd) {
  shutdown(fd, SHUT_WR);
  char buf[4096];
  while (recv(fd, buf, sizeof(buf), 0) > 0) {}
  close(fd);
}

static void *serve(void *arg) {
  Session *s = (Session *)arg;
  bool first = true;
  for (;;) {
    int fd = accept(listen_fd, nullptr, nullptr);
    if (fd < 0) continue;
    if (s->stop) { close(fd); break; }   // the wake-up connection from finish()
    if (first) {
      first = false;
      size_t off = 0;
      while (off < s->data.size()) {
        ssize_t n = send(fd, s->data.data() + off, s->data.size() - off, MSG_NOSIGNAL);
        if (n <= 0) break;
        off += (size_t)n;
      }
    }
    drain_close(fd);
  }
  return nullptr;
}

static void begin(Session &s, const uint8_t *d, size_t n) {
  s.data.assign(d, d + n);
  s.stop = false;
  pthread_create(&s.th, nullptr, serve, &s);
}

// Ends the session: wakes the accept loop with one last connection and joins the thread.
static void finish(Session &s) {
  s.stop = true;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons(port);
  connect(fd, (sockaddr *)&a, sizeof(a));
  close(fd);
  pthread_join(s.th, nullptr);
}

}  // namespace fake
