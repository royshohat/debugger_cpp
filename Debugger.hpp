#pragma once

#include <unistd.h>
#include <sys/user.h>
#include <string>
#include <vector>
#include <map>

class Debugger {
public:
    Debugger(pid_t pid) : m_pid(pid) {}

    // The main loop that asks for user input
    void run();

private:
    pid_t m_pid;
    std::map<long, long> m_breakpoints; // Address -> Original Data

    // Internal helpers
    void handle_command(const std::string& line);
    void continue_execution();
    void step_instruction();
    void set_breakpoint_at_address(long addr);
    void set_watchpoint_at_address(long addr);
    void dump_registers();
    void examine_memory(long addr);
    
    // Helper to wait and check if child exited
    void wait_for_signal();
    
    // Helper to split strings (moved from your main)
    std::vector<std::string> split(const std::string &s, char delimiter);
};

