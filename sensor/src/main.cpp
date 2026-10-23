#include "unwinder.hpp"

int main() {
    std::cout << "=======================================================\n";
    std::cout << "  StackSentry: Windows x64 Native Sensor Prototype     \n";
    std::cout << "=======================================================\n\n";

    StackSentry::StackUnwinder unwinder;
    auto frames = unwinder.CaptureCurrentStack();

    size_t index = 0;
    for (const auto& frame : frames) {
        std::cout << "Frame #" << index++ << ": 0x" << std::hex << frame.return_address << std::dec << "\n";
        std::wcout << L"  Module Path: " << frame.module_name << L"\n";
        std::cout << "  Backing Check: " << (frame.is_backed_by_file ? "PASS (MEM_IMAGE)" : "FAIL (UNBACKED / HEAP)") << "\n";
        std::cout << "  Opcode Check:  " << (frame.preceded_by_call_instruction ? "PASS (Valid CALL)" : "FAIL (No CALL Opcode)") << "\n";
        std::cout << "-------------------------------------------------------\n";
    }

    return 0;
}