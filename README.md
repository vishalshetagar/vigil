# Vigil — Linux Endpoint Security Sensor

Vigil turns kernel telemetry into process history and explainable behavioral alerts. It uses **C/eBPF** for collection and **Go** for processing, SQLite storage, rules, replay, and the CLI.

This is a working development MVP (`0.1.0-dev`), not a production-certified EDR. Live capture has been tested on Linux amd64 under WSL2. Replay and offline history queries also work on Windows. Nothing in Vigil blocks execution or terminates processes.

```text
fork / successful exec / task exit / connect syscall
                        |
                 C eBPF probes
                        |
               bounded ring buffer
                        |
                Go event processor
                  /            \
           process history   behavioral rules
                  \            /
              SQLite transactions
                        |
            Unix socket API + CLI

Recorded JSONL -> same processor and rules -> repeatable alerts
```

## What works

- Process creation, successful exec, thread exit, and last-thread exit events.
- Process identities based on deployment host ID, boot ID, **host PID**, and kernel birth time; PID reuse produces a new identity.
- Fork creator relationships, image generations within a sensor run, and historical events after processes exit.
- IPv4/IPv6 `connect` attempts and syscall results, including failed and nonblocking calls. `EINPROGRESS` is reported as pending.
- Four bounded rule types with evidence-bearing JSON alerts.
- SQLite transactions, duplicate event IDs, row-based retention, a database page budget, and read-only offline queries.
- Strict YAML config/rule validation, deterministic JSONL replay, capability diagnostics, loss counters, and live health reporting.
- Bounded queues/maps/state, graceful detach and drain, and restart with previously committed history preserved.

## Quick start without kernel privileges

Install **Go 1.26.3** and run from the repository root:

```sh
go build -o bin/vigil ./cmd/vigil
./bin/vigil rules validate
./bin/vigil replay --input testdata/replay/demo.jsonl --db demo.db
./bin/vigil alerts --db demo.db
./bin/vigil ps --db demo.db
./bin/vigil timeline --db demo.db --process demo-host/demo-boot/103/400
```

The demo produces **four alerts from seven events**. Replay writes alert JSONL to stdout and processing counters to stderr. With `--db`, each event and its alerts commit before they are printed. Replaying into the same database leaves stored event/alert IDs deduplicated; stdout still shows the deterministic evaluation of that replay.

On PowerShell, build `bin/vigil.exe` and invoke `./bin/vigil.exe`. Linux capture is unavailable on native Windows; use a suitable Linux VM or WSL2 distribution for that part.

## Live Linux capture

Required: Linux **amd64**, kernel BTF at `/sys/kernel/btf/vmlinux`, BPF ring buffers, raw scheduler tracepoints, connect syscall tracepoints, and permission to load and attach the programs. Kernel version alone is not a compatibility guarantee. The first tested environment is `6.18.33.2-microsoft-standard-WSL2`.

The generated BPF object is checked in and embedded, so ordinary builds and runtime capture do **not** require Clang, bpftool, or runtime C compilation.

```sh
make build
sudo ./bin/vigil doctor
sudo ./bin/vigil run --config configs/vigil.yaml
```

`doctor` performs actual loading and attachment, then releases its probes. A failed or inconclusive permission check returns a nonzero exit code with diagnostic output.

In another terminal:

```sh
sudo ./bin/vigil status
sudo ./bin/vigil events --type exec --limit 20
sudo ./bin/vigil alerts --limit 20
sudo ./bin/vigil ps
sudo ./bin/vigil inspect --process '<key from ps>'
sudo ./bin/vigil timeline --process '<key from ps>'
```

Use Ctrl+C or SIGTERM to detach, drain, commit pending records, and remove the socket. For a bounded session:

```sh
sudo ./bin/vigil run --duration 30s \
  --db /var/lib/vigil/history.db --socket /run/vigil/vigil.sock
```

Alerts go to stdout only after persistence; the final status goes to stderr. The read-only API uses an owner-only Unix socket, not a TCP listener. With a root-owned sensor, use `sudo` for socket queries. Offline `--db` queries never create a database or run migrations.

The system-wide probes observe **host-kernel** process identities. Inside PID namespaces, including WSL distributions, the PID in an event may differ from the PID shown by the local shell. A WSL kernel can host multiple distributions; capture is not limited to the launching distribution. `/etc/machine-id` labels the sensor deployment; a copied machine ID should be regenerated before deploying cloned hosts.

## Commands and output

| Command | Purpose |
| --- | --- |
| `doctor` | Inspect platform/BTF and try loading all required probes. |
| `run` | Capture, evaluate, persist, and serve local queries. |
| `status` | Live health; with `--db`, retained row counts. |
| `events` | Recent normalized events; optional `--type` and `--process`. |
| `ps` | Retained process snapshots, including exited processes. |
| `inspect --process KEY` | A retained process snapshot and its last observed exec. |
| `timeline --process KEY` | Retained events for one process instance. |
| `alerts` | Stored alerts with evidence snapshots. |
| `rules validate --rules FILE` | Validate a custom ruleset; omit the path for defaults. |
| `replay --input FILE` | Evaluate normalized JSONL without BPF privileges. |
| `version` | Print the development version. |

Queries return JSON arrays in **newest-first** order and default to 100 rows, with a maximum of 10,000. The process `key` is opaque; do not select historical identity by PID alone. `time_ns` is kernel monotonic time, not a UTC timestamp. Process `generation` is scoped to the snapshot's `run`.

For replaying captured data, export a single sensor run in oldest-first order. For example, using `jq` and the run ID reported by `status`:

```sh
sudo ./bin/vigil events --db /var/lib/vigil/history.db --limit 10000 \
  | jq -c --arg run '<sensor run ID>' 'reverse[] | select(.run == $run)' \
  > captured.jsonl
./bin/vigil replay --input captured.jsonl
```

This exports at most the requested retained rows, not an unlimited archival stream. Exporting only part of a run loses earlier context. Replay requires one host/boot/run per input, rejects malformed/unknown fields, and limits each input line to 64 KiB. Late records remain in persisted history but do not mutate newer graph state or trigger live/replay rules; a late-event counter and conservative coverage warnings make that visible.

## Detections

| Rule | Behavior | Interpretation |
| --- | --- | --- |
| VIGIL-001 | Configured server ancestry launches a shell | Requires observed executable ancestry; legitimate administration can match. |
| VIGIL-002 | Successful exec reports a filename beneath a configured temporary directory | A path heuristic; not proof of malicious content or resolved file identity. |
| VIGIL-003 | Shell/interpreter calls connect within the configured window after exec | Reports syscall outcome; not a confirmed reverse shell or established flow. |
| VIGIL-004 | Downloader exec precedes temporary-path exec under the same immediate creator | A bounded sequence; it does not prove the downloaded file was executed. |

Defaults are in [`internal/detect/default.yaml`](internal/detect/default.yaml). Copy that file to customize executable sets, directory sets, severities, windows, and cooldowns; supply it with `--rules` or the `rules` configuration key. A process name alone is never used as executable proof. Relative, truncated, or failed filename reads do not satisfy path predicates. Basename-based executable matching remains a heuristic and can be spoofed by renamed binaries.

Rules are parsed into typed predicates; arbitrary code execution is not supported. Windows and cooldowns are bounded to one hour. Rulesets are loaded at startup; changes require a restart. There is no hot reload, general expression language, or exception/suppression DSL yet.

## Configuration and failure behavior

[`configs/vigil.yaml`](configs/vigil.yaml) documents the defaults. Config paths are interpreted relative to the process working directory; use absolute paths for installed services.

| Budget | Default |
| --- | --- |
| Kernel ring | 16 MiB; configurable power of two, 4 KiB–256 MiB. |
| Pending connect map | 16,384 entries; failed insertions are counted. |
| Userspace queue | 8,192 fixed-size decoded kernel records. |
| Write batch | 256 records or 100 ms. |
| Process graph | 32,768 nodes, bounded recency eviction. |
| Rule state | 10,000 entries per global state map, including recent-ID cache. |
| Raw history / alerts | 50,000 / 10,000 most recent rows. |
| Database | 65,536 pages, normally 256 MiB; WAL and temporary space are additional. |

Retention is **row-based**, not a guarantee of a number of hours. Alert payloads retain their own evidence after raw-event deletion. WAL uses full synchronous commits and periodic checkpoints; its configured journal limit is not a hard total-disk cap. Long-running external readers can delay checkpoints. Keep the database on a local filesystem, not a network share.

Ring-buffer losses, map/read errors, userspace queue drops, malformed records, late events, graph evictions, and rule-state capacity drops are observable. Missing data does not silently satisfy predicates. Startup records an observation gap; subsequent gaps clear sequence state. Live health becomes degraded on collection/state loss. Persistent failure stops capture with a nonzero error; final status distinguishes committed and uncommitted records. Pending data is not recovered after a crash.

Use protected local directories. The default database and socket directories are created with mode `0700`; new database files and the socket use `0600`. Existing directory/file permissions are not automatically repaired. A leftover socket after a crash must be removed manually **after checking that no sensor is using it**; Vigil never deletes an existing socket to take it over.

## Development and tests

```sh
go test ./...
go vet ./...
go test -race ./...
go test ./internal/event -fuzz=FuzzDecode -fuzztime=10s -parallel=2
go test ./internal/replay -bench=BenchmarkReplayDemo -benchmem
```

Regenerate the embedded BPF code on Linux amd64 after editing C:

```sh
sudo apt-get install clang llvm libbpf-dev
make generate
make build
```

The checked-in object was generated with Clang 21.1.8 and libbpf headers 1.6.3 using Cilium eBPF v0.22.0. `go.mod`/`go.sum` pin Go dependencies. Minimal CO-RE type declarations live in the C source; kernel offsets are relocated using target BTF. Regeneration can change object bytes with a different compiler/header version; CI tests the freshly generated code rather than claiming byte-identical artifacts across toolchains.

Run real-kernel integration tests in a disposable Linux VM with C compiler and BPF privileges:

```sh
mkdir -p bin
go test -race -c -o bin/integration.test ./tests/integration
cd tests/integration
sudo env VIGIL_INTEGRATION=1 ../../bin/integration.test -test.v -test.timeout=60s
```

Ordinary `go test ./...` deliberately skips privileged integration. Explicitly enabled integration fails when privileges or required capabilities are missing. The workloads are benign: process creation, local executable replacement, thread exit, and loopback connections. No external callbacks or malware are used.

Coverage includes PID reuse, immutable creator edges, last-thread exit, non-leader exec, failed exec, successful/failed/pending IPv4/IPv6 connect, rule negatives/expiry/gaps, malformed input, bounded state, transactional rollback, storage-budget exhaustion, retention, socket ownership, full-ring drop accounting, live queries, shutdown, and restart. CI runs Windows/Linux unit tests, Linux race/vet checks, and a separate privileged Linux integration job.

## Optional systemd installation

The supplied unit is a **development root-service profile**. Its capability set has not been reduced or certified across distributions. Review it before installing on a persistent host.

```sh
sudo install -m 0755 bin/vigil /usr/local/bin/vigil
sudo install -d -m 0755 /etc/vigil
sudo install -m 0644 configs/vigil.yaml /etc/vigil/config.yaml
sudo install -m 0644 packaging/systemd/vigil.service /etc/systemd/system/vigil.service
sudo systemctl daemon-reload
sudo systemctl enable --now vigil
sudo journalctl -u vigil -f
```

No installation or service enablement happens automatically during development. To stop and uninstall the service, run `systemctl disable --now vigil`, then remove the installed unit/binary/config as appropriate; retained history is intentionally a separate operator decision.

## Current limits and next milestones

- No argv/environment capture, failed-exec attempt events, `/proc` bootstrap snapshot, executable hashing, or resolved file identity. Scripts may report the script filename rather than the interpreter image. A pre-existing server is unknown until relevant activity is observed.
- No file/credential probes, LSM enforcement, arm64 support, container-name enrichment, or fleet backend.
- Connect telemetry excludes inbound traffic, UDP `sendto`, established TCP state, socket inheritance/use, and mechanisms such as `io_uring` that bypass these syscall hooks. Negative results are outcomes, not necessarily attacks.
- The live graph and sequence state restart empty. Committed history is preserved, but live detection does not reconstruct old context on startup. A startup gap makes that boundary explicit.
- Sequence correlation currently covers the same immediate creator, not arbitrary descendant chains. There is no general allowlist DSL, automatic response, or alert-delivery retry/outbox.
- No complete causal ordering guarantee across CPUs. Late records are counted and skipped for state/rule evaluation rather than overwriting newer state.
- The tested WSL kernel is a development environment, not the planned distribution/kernel matrix. Throughput targets, 24-hour soak, least-privilege packaging, and release signing remain unverified.

Detailed implementation plans and execution/validation notes live in the Git-ignored `docs/` directory, per the repository's planning convention. They are not build inputs. The next work should close the history/argv/coverage gaps and establish the kernel/performance matrix before expanding to file telemetry or enforcement.

Implementation references: [Cilium eBPF Go workflow](https://ebpf-go.dev/guides/getting-started/), [kernel ring-buffer semantics](https://docs.kernel.org/bpf/ringbuf.html), [scheduler trace events](https://github.com/torvalds/linux/blob/master/include/trace/events/sched.h), and [SQLite WAL behavior](https://www.sqlite.org/wal.html).
