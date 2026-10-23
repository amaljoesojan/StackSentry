# StackSentry: Dynamic Call-Stack Graph Integrity Verification (Windows x64)

StackSentry is a host-based Endpoint Detection & Response (EDR) engine designed to detect in-memory evasion tactics—specifically synthetic call-stack spoofing and indirect system calls—on Windows x64 platforms.

## Architecture & Mechanics
1. **Native Sensor (`/sensor`):** Built with C++20 for x86_64 Windows. Intercepts execution points, walks thread stacks via Win32 `DbgHelp` / `RtlVirtualUnwind`, verifies preceding `CALL` opcodes (`0xE8`, `0xFF`), and checks memory backing (`MEM_IMAGE` vs `MEM_PRIVATE`).
2. **Verification Engine (`/engine`):** Python 3.11+ daemon parsing Windows Portable Executables (`pefile` / `capstone`) to construct static Directed Acyclic Graphs (DAGs) and validate runtime RVA transitions.
3. **Adversarial Harness (`/test_harness`):** Generates legitimate multithreaded stack traces and synthetic stack spoofing payloads for TPR/FPR benchmarking.

## Cloud Build Engine
Compiled automatically via GitHub Actions using the MSVC x64 toolchain (`cl.exe`). Native binaries are published as downloadable workflow artifacts.