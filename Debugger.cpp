#include "Debugger.hpp"
#include <iostream>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <iomanip>
#include <errno.h>
#include <cstddef> 


void Debugger::run() {
    // Initial wait for the child to start
    int status;
    waitpid(m_pid, &status, 0);
    std::cout << "Attached to process " << m_pid << std::endl;

    char* line = nullptr;
    while(true) {
        std::cout << "(minidbg) ";
        std::string input;
        if (!std::getline(std::cin, input)) break;
        handle_command(input);
    }
}

void Debugger::handle_command(const std::string& line) {
    auto args = split(line, ' ');
    if (args.empty()) return;
    std::string command = args[0];

    if (command == "c" || command == "continue") {
        continue_execution();
    }
    else if (command == "s" || command == "step") {
        step_instruction();
    }
    else if (command == "regs") {
        dump_registers();
    }
    else if (command == "b" || command == "break") {
        if (args.size() > 1) {
            long addr = std::stoul(args[1], nullptr, 16);
            set_breakpoint_at_address(addr);
        } else { std::cout << "Usage: b <addr>" << std::endl; }
    }
    else if (command == "w" || command == "watch") {
        if (args.size() > 1) {
            long addr = std::stoul(args[1], nullptr, 16);
            set_watchpoint_at_address(addr);
        } else { std::cout << "Usage: w <addr>" << std::endl; }
    }
    else if (command == "x") {
        if (args.size() > 1) {
            long addr = std::stoul(args[1], nullptr, 16);
            examine_memory(addr);
        } else { std::cout << "Usage: x <addr>" << std::endl; }
    }
    else if (command == "quit") {
        exit(0);
    }
    else {
        std::cout << "Unknown command\n";
    }
}

void Debugger::continue_execution() {
    // 1. Check if we are stopped at a breakpoint
    // (Logic: If RIP-1 is in map, restore original data, step back, then continue)
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
    
    // Check if we hit a breakpoint (RIP is one byte ahead of int3)
    if (m_breakpoints.count(regs.rip - 1)) {
        long addr = regs.rip - 1;
        
        // Restore instruction
        ptrace(PTRACE_POKETEXT, m_pid, addr, (void*)m_breakpoints[addr]);
        
        // Rewind RIP
        regs.rip = addr;
        ptrace(PTRACE_SETREGS, m_pid, 0, &regs);
        
        // Single step to execute the original instruction safely
        ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
        int status;
        waitpid(m_pid, &status, 0);

    }

    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void Debugger::step_instruction() {
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void Debugger::set_breakpoint_at_address(long addr) {
    long data = ptrace(PTRACE_PEEKTEXT, m_pid, addr, nullptr);
    m_breakpoints[addr] = data; // Save original
    
    long data_with_trap = (data & ~0xFF) | 0xCC;
    ptrace(PTRACE_POKETEXT, m_pid, addr, (void*)data_with_trap);
    std::cout << "Breakpoint set at 0x" << std::hex << addr << std::endl;
}

void Debugger::set_watchpoint_at_address(long addr) {
    // DR0
    long dr0_offset = offsetof(struct user, u_debugreg[0]);
    ptrace(PTRACE_POKEUSER, m_pid, dr0_offset, addr);

    // DR7
    long dr7_offset = offsetof(struct user, u_debugreg[7]);
    long dr7_config = 1 | (1 << 16) | (3 << 18);
    ptrace(PTRACE_POKEUSER, m_pid, dr7_offset, dr7_config);

    std::cout << "Watchpoint set at 0x" << std::hex << addr << std::endl;
}

void Debugger::dump_registers() {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
    std::cout << "RIP: 0x" << std::hex << regs.rip << std::endl;
    std::cout << "RSP: 0x" << std::hex << regs.rsp << std::endl;
}

void Debugger::examine_memory(long addr) {
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, m_pid, addr, nullptr);
    if(data == -1 && errno != 0) {
        std::cerr << "Cannot read memory.\n";
    } else {
        std::cout << "0x" << std::hex << addr << ": 0x" << data << std::endl;
    }
}

void Debugger::wait_for_signal() {
    int status;
    waitpid(m_pid, &status, 0);
    if (WIFEXITED(status)) {
        std::cout << "Process exited.\n";
        exit(0);
    }
}

std::vector<std::string> Debugger::split(const std::string &s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}
