#include <iostream>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>

int main(){

	pid_t pid = fork();
	if(pid==0){
		// we are in the child
		ptrace(PTRACE_TRACEME, 0, nullptr, nullptr); // flag that lets the father accsess this process memory, also right after exec the os checks for this flag and if is set then the process kicked out of the run queue, and wait for the parent to tell him when to run
		execl("/usr/bin/ls", "ls", nullptr); // exec with simple command 
	}

	int status;
	waitpid(pid, &status, 0); // waiting for the child to change status; should be "stopped" 

	
	struct user_regs_struct regs; // struct that the os uses to store all the regs

	ptrace(PTRACE_GETREGS, pid, nullptr, &regs); // here we fill the struct
	std::cout << "rip : 0x" << std::hex << regs.rip <<  std::endl; 

	long data = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, nullptr); // getting the data from rip; what is the next command

	std::cout << "data at rip : 0x" << data << std::endl;
	long opCode = data & 0xFF; // doing this end to check what is the op code, works only for little endian ofc
	std::cout << "the op code : 0x" << opCode << std::endl;
	// changing the op code to 0xCC (trap)
	long Newdata = data & ~0xFF; 
	Newdata = Newdata | 0xCC;

	// changing the memory in rip so the next command will be with the trap op code
	ptrace(PTRACE_POKETEXT, pid, regs.rip, Newdata);
	long dataCheck = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, nullptr);
	std::cout << "data at rip : 0x" << dataCheck << std::endl;


	// continue, should stop one step later because of the trap we sat
	ptrace(PTRACE_CONT, pid, nullptr, nullptr);
	waitpid(pid, &status, 0);

	if(WIFSTOPPED(status)){
			
		std::cout << "child stopped!" << std::endl;
	
		// after we set the break point, we want to run the commend we vandlised
		// this is that doing
		ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
		regs.rip -= 1;
		ptrace(PTRACE_SETREGS, pid, nullptr, &regs);

		ptrace(PTRACE_POKETEXT, pid, regs.rip, data);
	}

	ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);

	waitpid(pid, &status, 0);
	std::cout << "child executed one instruction" << std::endl;
	ptrace(PTRACE_CONT, pid, nullptr, nullptr);
	waitpid(pid, &status, 0);

}
