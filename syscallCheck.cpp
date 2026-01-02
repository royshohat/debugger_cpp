#include <iostream>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(){
	pid_t childPid = fork();
	if (childPid == 0){
		// means we are in the child
		ptrace(PTRACE_TRACEME, 0, nullptr, nullptr); // making the parent able to trace me 
		execl("/usr/bin/ls", "ls", nullptr);
		std::cerr << "execve failed\n";
		exit(1);
	}

	int status;	
	waitpid(childPid, &status, 0);
	struct user_regs_struct regs;

	std::cout << std::hex;
	bool is_entry = true; 

    while(!WIFEXITED(status)){
        
        ptrace(PTRACE_SYSCALL, childPid, 0, 0);
        waitpid(childPid, &status, 0);

        if(WIFEXITED(status)) break;

        if(is_entry) {
            ptrace(PTRACE_GETREGS, childPid, 0, &regs);

            if(regs.orig_rax == 1) { // Syscall 1 is WRITE
                std::cout << "\n[Write Detected]" << std::endl;
                std::cout << "Length: " << std::dec << regs.rdx << " bytes" << std::endl;
                
                unsigned long long current_addr = regs.rsi;
                unsigned long long total_read = 0;
                
                // Only read as many bytes as the write length (regs.rdx)
                while(total_read < regs.rdx) {
                    long data = ptrace(PTRACE_PEEKDATA, childPid, current_addr, nullptr);
                    char* chars = (char*)&data;

                    for(int i=0; i < 8 && total_read < regs.rdx; i++) {
                        std::cout << chars[i];
                        total_read++;
                    }
                    current_addr += 8; // Advance 8 bytes
                }
                std::cout << std::endl;
            }
        }

        is_entry = !is_entry;
    }


}
