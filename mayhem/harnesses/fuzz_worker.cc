// libgearman worker: parse server replies (NOOP, NO_JOB, JOB_ASSIGN / _UNIQ / _ALL, errors...).
// Byte 0 is a selector. Its low two bits pick how the worker asks for work: 0 GRAB_JOB_ALL (the
// default), 1 GRAB_JOB_UNIQ, 2 or 3 plain GRAB_JOB, which changes the job-assign reply the worker
// expects. A fake server on loopback answers the worker's first connection with the rest of the
// fuzz bytes and then closes, so
// gearman_worker_work() ends on EOF. The registered function echoes the workload back through the
// job API so the job-side parsing (handle, unique, workload, reducer) is used.
//
// Reply framing (fuzz_client.cc's scheme, with a narrower raw selector): unless the selector
// picks raw mode, the harness puts the binary reply magic "\0RES" in front of the fuzz bytes, so
// they start at the first packet's command field. With (sel & 0xF8) == 0xD0 the bytes go out raw,
// so text replies and bad magic stay reachable. No reply is rejected. The framing only keeps
// libFuzzer's first inputs ("\n", "\n\n", ...) off the upstream text-reply NULL store in
// gearman_packet_unpack() (`if (!ptr) *ptr= 0;`, libgearman/packet.cc); without it Mayhem's
// -runs=5 sanity check can crash on the first few inputs.
#include <libgearman/gearman.h>
#include <vector>
#include "fake_server.h"

static gearman_return_t fn(gearman_job_st *job, void *) {
  const char *h = gearman_job_handle(job);
  const char *u = gearman_job_unique(job);
  (void)h; (void)u;
  gearman_job_send_status(job, 1, 2);
  return gearman_job_send_data(job, gearman_job_workload(job), gearman_job_workload_size(job)) ==
                 GEARMAN_SUCCESS
             ? GEARMAN_SUCCESS
             : GEARMAN_ERROR;
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  fake::start();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  const uint8_t sel = data[0];
  fake::Session s;
  if ((sel & 0xF8) == 0xD0) {
    fake::begin(s, data + 1, size - 1);
  } else {
    static const uint8_t magic[] = {0, 'R', 'E', 'S'};
    std::vector<uint8_t> reply(magic, magic + sizeof(magic));
    reply.insert(reply.end(), data + 1, data + size);
    fake::begin(s, reply.data(), reply.size());
  }
  gearman_worker_st *worker = gearman_worker_create(nullptr);
  switch (sel & 0x03) {
    case 0:  // as created: GRAB_JOB_ALL
      break;
    case 1:
      gearman_worker_remove_options(worker, GEARMAN_WORKER_GRAB_ALL);
      gearman_worker_add_options(worker, GEARMAN_WORKER_GRAB_UNIQ);
      break;
    default:  // 2, 3: plain GRAB_JOB
      gearman_worker_remove_options(worker,
                                    gearman_worker_options_t(GEARMAN_WORKER_GRAB_ALL | GEARMAN_WORKER_GRAB_UNIQ));
      break;
  }
  gearman_worker_add_server(worker, "127.0.0.1", fake::port);
  gearman_function_t f = gearman_function_create(fn);
  gearman_worker_define_function(worker, "f", 1, f, 0, nullptr);
  // Blocking gearman_worker_work() reconnects forever once the server hangs up, so step the
  // state machine in non-blocking mode a bounded number of times instead (no timer involved).
  gearman_worker_add_options(worker, GEARMAN_WORKER_NON_BLOCKING);
  for (int i = 0; i < 32; i++) {
    gearman_return_t rc = gearman_worker_work(worker);
    if (rc == GEARMAN_IO_WAIT) {
      if (gearman_worker_wait(worker) != GEARMAN_SUCCESS) break;
    } else if (rc != GEARMAN_SUCCESS && rc != GEARMAN_NO_JOBS) {
      break;
    }
  }
  gearman_worker_remove_servers(worker);
  gearman_worker_free(worker);
  fake::finish(s);
  return 0;
}
