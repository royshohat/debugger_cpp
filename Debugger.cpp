#include "Debugger.hpp"
#include <iostream>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <iomanip>
#include <errno.h>
#include <cstddef> 
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>


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
			// Use the new helper!
			long addr = get_addr_from_symbol(args[1]);
			if (addr == 0) {
				std::cout << "Symbol not found or invalid address" << std::endl;
			} else {
				set_breakpoint_at_address(addr);
			}
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
		long data = m_breakpoints[addr];

        // Restore instruction
        ptrace(PTRACE_POKETEXT, m_pid, addr, (void*)data);
        
        // Rewind RIP
        regs.rip = addr;
        ptrace(PTRACE_SETREGS, m_pid, 0, &regs);
        
        // Single step to execute the original instruction safely
        ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
        int status;
        waitpid(m_pid, &status, 0);

		// Rewrite the trap instruction
		long data_with_trap = (data & ~0xFF) | 0xCC;
		ptrace(PTRACE_POKETEXT, m_pid, addr, (void*)data_with_trap);

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

    std::cout << "--- Registers ---" << std::endl;
    
    // Helper lambda to print a register neatly aligned
    auto print_reg = [](const std::string& name, unsigned long long value) {
        std::cout << std::left << std::setw(4) << name << ": 0x" 
                  << std::setw(16) << std::setfill('0') << std::hex << value 
                  << std::setfill(' ') << std::dec << std::endl;
    };

    // General Purpose
    print_reg("RAX", regs.rax);
    print_reg("RBX", regs.rbx);
    print_reg("RCX", regs.rcx);
    print_reg("RDX", regs.rdx);
    
    // Index & Pointers
    print_reg("RSI", regs.rsi);
    print_reg("RDI", regs.rdi);
    print_reg("RBP", regs.rbp);
    print_reg("RSP", regs.rsp);
    
    // Instruction Pointer
    print_reg("RIP", regs.rip);

    // Extended Registers (R8-R15)
    print_reg("R8 ", regs.r8);
    print_reg("R9 ", regs.r9);
    print_reg("R10", regs.r10);
    print_reg("R11", regs.r11);
    print_reg("R12", regs.r12);
    print_reg("R13", regs.r13);
    print_reg("R14", regs.r14);
    print_reg("R15", regs.r15);

    // Flags
    print_reg("EFLAGS", regs.eflags);
    
    // Segment Registers (Optional but good to have)
    print_reg("CS", regs.cs);
    print_reg("SS", regs.ss);
    print_reg("DS", regs.ds);
    print_reg("ES", regs.es);
    print_reg("FS", regs.fs);
    print_reg("GS", regs.gs);

    std::cout << "-----------------" << std::endl;
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

void Debugger::load_symbols(const std::string& filename) {
	// Opening the binary file; Only read cause we are only mapping symbols to address
	int fd = open(filename.c_str(), O_RDONLY);
	if(fd < 0) {
		std::cerr << "Couldn't open file\n";
		return;
	}
	
	// Getting the stats of the file;
	struct stat st;
	fstat(fd, &st);

	// Some mmap stuff
	void* map_start = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map_start == MAP_FAILED) {
        close(fd);
        std::cerr << "Failed to map file." << std::endl;
        return;
    }

	// "Pointer" to the start of the header
	Elf64_Ehdr* ehdr = (Elf64_Ehdr*)map_start;

	// "Pointer" to the section headers
	Elf64_Shdr* shdrs = (Elf64_Shdr*)((char*)map_start + ehdr->e_shoff);

	// We will just relay on the integer type
	//// Finding the string table for section names
	//// Needed to look for .symtab
	//Elf64_Shdr* sh_strtab = &shdrs[ehdr->e_shstrndx];
    //const char* sh_strtab_p = (char*)map_start + sh_strtab->sh_offset;

	// Itrate over the sections until we find symtab or dynamic sym
	for (int i = 0; i < ehdr->e_shnum; ++i) {
        
        // We are looking for SHT_SYMTAB or SHT_DYNSYM (dynamic symbols)
        if (shdrs[i].sh_type == SHT_SYMTAB || shdrs[i].sh_type == SHT_DYNSYM) {
            
            // Found a symbol table! Now point to it.
            Elf64_Sym* syms = (Elf64_Sym*)((char*)map_start + shdrs[i].sh_offset);
            
            // We also need the String Table for the *symbols* themselves
            // The symbol table header has a link to its string table index
            Elf64_Shdr* strtab_hdr = &shdrs[shdrs[i].sh_link];
            const char* strtab_p = (char*)map_start + strtab_hdr->sh_offset;

            // Calculate how many symbols are in this table
            int num_symbols = shdrs[i].sh_size / sizeof(Elf64_Sym);

            // Iterate the symbols
            for (int j = 0; j < num_symbols; ++j) {
                std::string name = strtab_p + syms[j].st_name;
                long addr = syms[j].st_value;

                // Only store functions and existing symbols
                if (!name.empty() && addr != 0) {
                    m_symbol_lookup[name] = addr;
                }
            }
        }
    }
	munmap(map_start, st.st_size);
	close(fd);

}

long Debugger::get_addr_from_symbol(const std::string& name) {
    if (m_symbol_lookup.count(name)) {
        return m_symbol_lookup[name];
    }
    // If not found, try to parse as hex
    try {
        return std::stoul(name, nullptr, 16);
    } catch(...) {
        return 0;
    }
}
