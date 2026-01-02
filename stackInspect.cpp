#include <sys/ptrace.h>
#include <sys/wait.h> 
#include <sys/user.h> 
#include <unistd.h>
#include <iostream>

int main(){
	pid_t childPid = fork();
	if (childPid == 0){
		// means we are in the child
		ptrace(PTRACE_TRACEME, 0, nullptr, nullptr); // making the parent able to trace me 
		execl("/usr/bin/ls", "ls", nullptr);
		std::cerr << "execve failed\n";
		exit(1);
	}
	// cause of execve the child wont get here
	
	int status;
	waitpid(childPid, &status, 0);
	// coping the child regs to this struct
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, childPid, nullptr, &regs);
	
	// printing rsp
	std::cout << "rsp : 0x" << std::hex << regs.rsp << std::dec << std::endl;

	// printing the data inside the address of rsp (should be argc)
	// also the cpu is alignning the int arc so it is padding it with zeros for cpu convenience
	long dataAtRsp = ptrace(PTRACE_PEEKDATA, childPid, (void*)regs.rsp, nullptr); 
	std::cout << "data at rsp : 0x" << std::hex << dataAtRsp << std::endl;
	
	// should be argv[0]; still a pointer to the first arg tho
	long dataAtRspPlus8 = ptrace(PTRACE_PEEKDATA, childPid, (void*)regs.rsp+8, nullptr);
	std::cout << std::hex << "data at rsp+8 : 0x" << dataAtRspPlus8 << std::dec << std::endl;

	// should be argv[1][0]; finnaly the actual string; that should be 'l' 's' then end line; keep in note that even tho it is char* we are reading as long
	// that is because of how ptrace peekdata is built; we will interpert it later
	long dataAtDataAtRspPlus8 = ptrace(PTRACE_PEEKDATA, childPid, dataAtRspPlus8, nullptr);
	
	// making it char* to print it char by char
	char* rawPtr = reinterpret_cast<char*>(&dataAtDataAtRspPlus8);
	for(int i=0; i<sizeof(long); ++i)
		std::cout << rawPtr[i];
	std::cout << std::hex << std::endl;
	for(int i=0; i<sizeof(long); ++i)
		std::cout << "0x" << (int)rawPtr[i] << " ";
	std::cout << std::endl;

}	

