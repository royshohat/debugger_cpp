#include <iostream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string>
#include <vector>
#include <sstream>
#include <map>

std::map<long, long> breakpoints; // save break points as address -> original data

// Helper to split string by spaces
std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

int main(){
    pid_t childPid = fork();
    if(childPid == 0){
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl("/usr/bin/ls", "ls", nullptr);
        exit(1);
    }

    int status;
    waitpid(childPid, &status, 0); // Wait for start
    std::cout << "Process started. PID: " << childPid << std::endl;

	struct user_regs_struct regs;		

	while(true) {
		// Check for hit
        ptrace(PTRACE_GETREGS, childPid, nullptr, &regs);
        
        // Note: We check 'rip - 1' because the trap (0xCC) has already executed, moving RIP forward.
        if(breakpoints.count(regs.rip - 1)){
            long addr = regs.rip - 1;
            
            std::cout << "Hit breakpoint at 0x" << std::hex << addr << std::endl;

			// rip back to normal
            regs.rip = addr;
            ptrace(PTRACE_SETREGS, childPid, 0, &regs);

			// restore the code
            long orig_data = breakpoints[addr];
            ptrace(PTRACE_POKETEXT, childPid, addr, (void*)orig_data);

            breakpoints.erase(addr);
        }

        std::cout << "(minidbg) ";
        std::string input;
        if(!std::getline(std::cin, input)) break;
        std::vector<std::string> args = split(input, ' ');
        if(args.empty()) continue;
        std::string command = args[0];

        if (command == "c" || command == "continue") {
			ptrace(PTRACE_CONT, childPid, nullptr, nullptr);
			waitpid(childPid, &status, 0);
        } 
        else if (command == "s" || command == "step") {
			ptrace(PTRACE_SINGLESTEP, childPid, nullptr, nullptr);
			waitpid(childPid, &status, 0);
        } 
		else if (command == "b" || command == "break"){
			if (args.size() != 2){
				std::cerr << "usage: b <address>" << std::endl;
				continue;
			}
			long addr = std::stoul(args[1], nullptr, 16); // 16 is the base as in hex
			breakpoints[addr] = ptrace(PTRACE_PEEKDATA, childPid, addr, nullptr);
			long trapedData = breakpoints[addr];
			trapedData = (trapedData & ~0xFF) | 0xCC;
			ptrace(PTRACE_POKEDATA, childPid, addr, (void*)trapedData);

		}
		else if(command == "w" || command == "watch"){
			if(args.size() != 2){
				std::cerr << "usage: w <address>" << std::endl;
				continue;
			}

			// the user will input the address as hex but without 0x
			long addr = std::stoul(args[1], nullptr, 16); // 16 is the base as in hex
			
			// Calc the offset for dr0, dr7
			long dr0_offset = offsetof(struct user, u_debugreg[0]);
			long dr7_offset = offsetof(struct user, u_debugreg[7]);

			// Writing the address of the thing the user wants to watch to dr7
			errno = 0;
			ptrace(PTRACE_POKEUSER, childPid, dr0_offset, addr);
			if(errno != 0){
				std::cerr << "failed to set DR0\n";
				continue;
			}

			long dr7_conf = 1 | (1 << 16) | (3 << 18);

			ptrace(PTRACE_POKEUSER, childPid, dr7_offset, dr7_conf);

			std::cout << "HARDWARE watchpoint set on : 0x" << std::hex << addr << std::endl;
		}

		else if(command == "x" || command == "examine"){
			if(args.size() != 2){
				std::cerr << "usage: x <address>" << std::endl;
				continue;
			}

			// the user will input the address as hex but without 0x
			long addr = std::stoul(args[1], nullptr, 16); // 16 is the base as in hex

			errno = 0;
			long data = ptrace(PTRACE_PEEKDATA, childPid, addr, nullptr);
			
			// checks if the read was valid 
			if(data == -1 && errno != 0){
				std::cerr << "Error: Could not read memory at 0x" << args[1] << std::endl;
			}else{
				std::cout << "data at " << addr << " : 0x" << std::hex << data << std::dec << std::endl;
			}

		}
        else if (command == "regs") {
			ptrace(PTRACE_GETREGS, childPid, nullptr, &regs); 
			std::cout << "rip : 0x" << std::hex << regs.rip << std::endl;
			std::cout << "rsp : 0x" << std::hex << regs.rsp << std::endl;
        }
        else if (command == "quit") {
            break;
        }
        else {
            std::cout << "Unknown command" << std::endl;
        }

        // Check if child is dead after a step/continue
        if (WIFEXITED(status)) {
            std::cout << "Child exited with code " << WEXITSTATUS(status) << std::endl;
            break;
        }
    }
}
