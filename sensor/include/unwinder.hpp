#pragma once

#include <windows.h>
#include <winternl.h>
#include <dbghelp.h>
#include <iostream>
#include <vector>
#include <cstdint>

namespace StackSentry {

    struct StackFrameInfo {
        uint64_t return_address;
        uint64_t module_base;
        wchar_t  module_name[MAX_PATH];
        bool     is_backed_by_file;
        bool     preceded_by_call_instruction;
        uint8_t  preceding_bytes[8];
    };

    class StackUnwinder {
    public:
        StackUnwinder();
        ~StackUnwinder();

        // Capture and inspect the current thread's call stack
        std::vector<StackFrameInfo> CaptureCurrentStack();

    private:
        bool VerifyCallOpcode(uint64_t return_addr, uint8_t* out_bytes);
        bool IsAddressBackedByModule(uint64_t address, uint64_t& out_base, wchar_t* out_name);
    };

} // namespace StackSentry