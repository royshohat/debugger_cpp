#pragma once

#include <unistd.h>
#include <sys/user.h>
#include <string>
#include <vector>
#include <map>

class Debugger {
public:
    Debugger(pid_t pid, const std::string& filename) : m_pid(pid) { load_symbols(filename); }

    // The main loop that asks for user input
    void run();

private:
    pid_t m_pid;
    std::map<long, long> m_breakpoints; // Address -> Original Data
	std::map<std::string, long> m_symbol_lookup; // Symbol -> Address

    // Internal helpers
    void handle_command(const std::string& line);
    void continue_execution();
    void step_instruction();
    void set_breakpoint_at_address(long addr);
    void set_watchpoint_at_address(long addr);
    void dump_registers();
    void examine_memory(long addr);
	void load_symbols(const std::string& filename);
	long get_addr_from_symbol(const std::string& symbol);
    
    // Helper to wait and check if child exited
    void wait_for_signal();
    
    // Helper to split strings 
    std::vector<std::string> split(const std::string &s, char delimiter);
};

