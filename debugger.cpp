#include <iostream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string>
#include <vector>
#include <sstream>

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
        // 1. Print Prompt
        std::cout << "(minigdb) ";
        
        // 2. Get Input
        std::string input;
        if(!std::getline(std::cin, input)) break;
        std::vector<std::string> args = split(input, ' ');
        if(args.empty()) continue;
        std::string command = args[0];

        // 3. Handle Commands
        if (command == "c" || command == "continue") {
			ptrace(PTRACE_CONT, childPid, nullptr, nullptr);
			waitpid(childPid, &status, 0);
        } 
        else if (command == "s" || command == "step") {
			ptrace(PTRACE_SINGLESTEP, childPid, nullptr, nullptr);
			waitpid(childPid, &status, 0);
        } 
		else if(command == "x" || command == "examine"){
			if(args.size() < 2){
				std::cout << "usage: x <address>" << std::endl;
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
