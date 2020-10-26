# About

This is a collection of examples showing the usage of BPF ringbuf and perfbuf
APIs. Each example implements a simple tracing tool, collecting all exec()
syscalls, which correspond to starting a new processes:
  - `perfbuf-output` uses BPF perfbuf and `bpf_perf_event_output()` API;
  - `ringbuf-output` uses BPF ringbuf and `bpf_ringbuf_output()` API, very
     similar to the one provided by BPF perfbuf;
  - `ringbuf-reserve-commit` shows off a distinct BPF ringbuf's
    `bpf_ringbuf_reserve()`/`bpf_ringbuf_submit()` pair of APIs, which provide
    better usability and performance, compared to the `xxx_output()` APIs.

These examples are a companion to the [BPF ring buffer blog
post](https://nakryiko.com/posts/bpf-ringbuf/).

# Building & running

This repo is using libbpf through submodule at libbpf/. It also has a copy of
bpftool binary (built fro x86-64 platform), which is used to generate BPF
skeleton for .bpf.c files. These examples do not rely on BPF CO-RE and thus
there are no extra requirements on Linux kernel, beyond some reasonably recent
version for BPF perfbuf version, while BPF ringbuf examples need 5.8+ kernels.

Otherwise, everything is super straightforward:

```shell
$ git submodule update --init --recursive       # check out libbpf
$ cd src
$ make
$ sudo ./ringbuf-reserve-commit    # or ./ringbuf-output, or ./perfbuf-output
TIME     EVENT PID     COMM             FILENAME
19:17:39 EXEC  3232062 sh               /bin/sh
19:17:39 EXEC  3232062 timeout          /usr/bin/timeout
19:17:39 EXEC  3232063 ipmitool         /usr/bin/ipmitool
19:17:39 EXEC  3232065 env              /usr/bin/env
19:17:39 EXEC  3232066 env              /usr/bin/env
19:17:39 EXEC  3232065 timeout          /bin/timeout
19:17:39 EXEC  3232066 timeout          /bin/timeout
19:17:39 EXEC  3232067 sh               /bin/sh
19:17:39 EXEC  3232068 sh               /bin/sh
^C
```
