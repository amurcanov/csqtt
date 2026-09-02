<!-- SPDX-FileCopyrightText: 2026 amurcanov -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# csqtt dataplane

Toolchain target: Rust 1.97.1, edition 2024, x86_64-unknown-linux-musl.

The packet data plane runs on one dedicated thread hosting a `current_thread` Tokio runtime created once per attempt; UDP and TUN I/O go through epoll readiness (`AsyncFd`, `try_io`) with the client's syscall semantics: `recvmmsg` (`MSG_DONTWAIT|MSG_WAITFORONE`) on receive and `sendmmsg` (`MSG_DONTWAIT`) on transmit. All buffers live in fixed pools allocated at startup — `recvmmsg` batch slots, `UDP_TX_SLOTS`, `TUN_TX_SLOTS` — so steady-state RSS never grows beyond that ceiling. The hot path is allocation-free and sans-io: `tokio_io.rs` performs I/O only, all protocol decisions stay in `protocol.rs` behind the `PacketSink`/`DataplaneLogic` traits.

The event loop is a single biased `tokio::select!`; commands arrive through a bounded `tokio::sync::mpsc`, wake-ups come from readiness events rather than polling. Per-stream Tokio mpsc packet fanout and O(N) worker probing are deliberately not used by the TUN route path. Fatal dataplane termination is surfaced to `main.rs`, which performs orderly server shutdown so an external process supervisor can restart the process.

Run `build_linux.bat --tests` or `./build_linux.sh --tests` before making a release asset.

Both scripts verify formatting, compile all Linux musl targets, and run Clippy with warnings denied. `build_linux.bat` runs the same checks in CI by default and **compiles** Linux musl test binaries; Windows cannot execute those ELF binaries. On a Linux host, `build_linux.sh --tests` also **executes** the Linux musl test suite. The final release binaries are linked for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, and `armv7-unknown-linux-musleabihf`, then copied to `app/src/main/assets/csqtt-linux-amd64`, `csqtt-linux-arm64`, and `csqtt-linux-armv7`; they are selected from the VPS architecture before upload.
