#include "Debugger.hpp"
#include <iostream>
#include <sys/ptrace.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./minidbg <program_name>\n";
        return -1;
    }

    auto prog = argv[1];
    pid_t pid = fork();

    if (pid == 0) {
        // Child
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(prog, prog, nullptr);
        std::cerr << "Failed to exec\n";
    }
    else if (pid >= 1)  {
        // Parent
        Debugger dbg(pid);
        dbg.run();
    }
}
