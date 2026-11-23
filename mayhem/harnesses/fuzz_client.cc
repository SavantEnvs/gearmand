// libgearman client: parse server replies. A fake server on loopback answers the client's first
// connection with the fuzz bytes (after the first selector byte) and then closes, so each call
// ends on EOF. The selector picks which public client API drives the reply state machine.
//
// Reply framing: unless the selector picks raw mode (below), the harness puts the binary reply magic
// "\0RES" in front of the fuzz bytes, so the bytes start at the first packet's command field.
// With (sel & 0xC8) == 0xC0 (bits 7 and 6 set, bit 3 clear, so not the 0xff libFuzzer likes to
// insert) the bytes go out raw, so text replies and bad magic stay reachable.
// No reply is rejected. The framing only keeps libFuzzer's first inputs ("\n", "\n\n", ...)
// off the upstream text-reply NULL store in gearman_packet_unpack() (`if (!ptr) *ptr= 0;`,
// libgearman/packet.cc), which any non-binary first reply line without a space reaches. Without
// it, Mayhem's -runs=5 sanity check crashes on the second or third input.
#include <libgearman/gearman.h>
#include <cstdlib>
#include "fake_server.h"

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  fake::start();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  uint8_t sel = data[0];
  fake::Session s;
  if ((sel & 0xC8) == 0xC0) {
    fake::begin(s, data + 1, size - 1);
  } else {
    static const uint8_t magic[] = {0, 'R', 'E', 'S'};
    std::vector<uint8_t> reply(magic, magic + sizeof(magic));
    reply.insert(reply.end(), data + 1, data + size);
    fake::begin(s, reply.data(), reply.size());
  }

  gearman_client_st *client = gearman_client_create(nullptr);
  gearman_client_add_server(client, "127.0.0.1", fake::port);
  if (sel & 0x10) gearman_client_add_options(client, GEARMAN_CLIENT_UNBUFFERED_RESULT);
  if (sel & 0x20) gearman_client_add_options(client, GEARMAN_CLIENT_GENERATE_UNIQUE);
  static const char workload[] = "fuzz-workload";
  switch (sel % 6) {
    case 0: {
      size_t rsize = 0;
      gearman_return_t rc;
      void *r = gearman_client_do(client, "f", nullptr, workload, sizeof(workload) - 1, &rsize, &rc);
      free(r);
      break;
    }
    case 1: {
      size_t rsize = 0;
      gearman_return_t rc;
      void *r = gearman_client_do_high(client, "f", "u1", workload, sizeof(workload) - 1, &rsize, &rc);
      free(r);
      break;
    }
    case 2: {
      gearman_job_handle_t h;
      gearman_client_do_background(client, "f", nullptr, workload, sizeof(workload) - 1, h);
      break;
    }
    case 3: {
      bool known = false, running = false;
      uint32_t num = 0, den = 0;
      gearman_client_job_status(client, "H:fuzz:1", &known, &running, &num, &den);
      break;
    }
    case 4:
      gearman_client_echo(client, workload, sizeof(workload) - 1);
      break;
    case 5: {
      gearman_argument_t arg = gearman_argument_make(nullptr, 0, workload, sizeof(workload) - 1);
      gearman_task_st *t = gearman_execute(client, "f", 1, nullptr, 0, nullptr, &arg, nullptr);
      if (t) gearman_task_free(t);
      break;
    }
  }
  gearman_client_free(client);
  fake::finish(s);
  return 0;
}
