#include "unwinder.hpp"

#pragma comment(lib, "Dbghelp.lib")

namespace StackSentry {

    StackUnwinder::StackUnwinder() {
        SymInitialize(GetCurrentProcess(), NULL, TRUE);
    }

    StackUnwinder::~StackUnwinder() {
        SymCleanup(GetCurrentProcess());
    }

    bool StackUnwinder::IsAddressBackedByModule(uint64_t address, uint64_t& out_base, wchar_t* out_name) {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        // Must be committed memory backed by an executable image on disk (MEM_IMAGE)
        if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE) {
            out_base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            wcscpy_s(out_name, MAX_PATH, L"UNBACKED_MEMORY");
            return false;
        }

        out_base = reinterpret_cast<uint64_t>(mbi.AllocationBase);
        if (GetModuleFileNameW(reinterpret_cast<HMODULE>(out_base), out_name, MAX_PATH) == 0) {
            wcscpy_s(out_name, MAX_PATH, L"UNKNOWN_MODULE");
        }

        return true;
    }

    bool StackUnwinder::VerifyCallOpcode(uint64_t return_addr, uint8_t* out_bytes) {
        if (!return_addr) return false;

        // Read up to 8 bytes preceding the return address
        uint8_t* code_ptr = reinterpret_cast<uint8_t*>(return_addr - 8);
        
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (VirtualQuery(code_ptr, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT) {
            return false;
        }

        memcpy(out_bytes, code_ptr, 8);

        // Check common x86_64 call opcodes:
        // 0xE8 xx xx xx xx  -> CALL rel32 (5 bytes)
        // 0xFF /2           -> CALL r/m64 (2 to 3 bytes, e.g., FF D0 for call rax)
        uint8_t byte_minus_5 = out_bytes[3]; // return_addr - 5
        uint8_t byte_minus_2 = out_bytes[6]; // return_addr - 2

        if (byte_minus_5 == 0xE8) {
            return true; // Relative CALL
        }
        if (byte_minus_2 == 0xFF) {
            return true; // Indirect CALL
        }

        return false;
    }

    std::vector<StackFrameInfo> StackUnwinder::CaptureCurrentStack() {
        std::vector<StackFrameInfo> frames;

        CONTEXT context = { 0 };
        context.ContextFlags = CONTEXT_FULL;
        RtlCaptureContext(&context);

        DWORD64 image_type = IMAGE_FILE_MACHINE_AMD64;
        HANDLE process = GetCurrentProcess();
        HANDLE thread = GetThreadCurrent();

        STACKFRAME64 stack_frame = { 0 };
        stack_frame.AddrPC.Offset    = context.Rip;
        stack_frame.AddrPC.Mode      = AddrModeFlat;
        stack_frame.AddrFrame.Offset = context.Rsp;
        stack_frame.AddrFrame.Mode   = AddrModeFlat;
        stack_frame.AddrStack.Offset = context.Rsp;
        stack_frame.AddrStack.Mode   = AddrModeFlat;

        while (StackWalk64(image_type, process, thread, &stack_frame, &context,
                           NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
            
            if (stack_frame.AddrPC.Offset == 0) break;

            StackFrameInfo info = { 0 };
            info.return_address = stack_frame.AddrPC.Offset;
            
            info.is_backed_by_file = IsAddressBackedByModule(
                info.return_address, info.module_base, info.module_name
            );

            info.preceded_by_call_instruction = VerifyCallOpcode(
                info.return_address, info.preceding_bytes
            );

            frames.push_back(info);
        }

        return frames;
    }

} // namespace StackSentry