# debugger_cpp
Description: A minimal Linux debugger for x86_64 architectures implemented in C++.

Overview:
This tool demonstrates the fundamentals of process tracing and low-level system interaction. It utilizes the ptrace() system call to control process execution, manipulate memory, and inspect CPU state. It includes a custom ELF parser to map function names to memory addresses, allowing for symbolic breakpoints.

Key Features:
- Process Control: Step instruction, continue, fork.
- Software Breakpoints: Implemented via opcode injection (0xCC / INT 3) and instruction restoration.
- Hardware Watchpoints: Utilizes x86 Debug Registers (DR0-DR7) to trap memory access without software overhead.
- Register & Memory Inspection: Direct access to user_regs_struct and raw memory via PTRACE_PEEK.
- Symbol Resolution: Custom ELF parsing (via <elf.h> and mmap) to resolve function names to static addresses.

Build Instructions:
$ g++ -std=c++11 main.cpp Debugger.cpp -o minidbg

Usage Notes:
Target programs must be compiled with '-no-pie' to disable ASLR for symbol resolution.
$ ./minidbg <target_executable>
(minidbg) break main
(minidbg) continue
(minidbg) regs // prints all the importent regs

