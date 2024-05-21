#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    pid_t child = fork();
    if (child == 0) {
        // Child process: stop itself for ptrace attachment
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);
        // Load and execute the script or executable here
        execl("testlooper.sh", "testlooper.sh", (char *)NULL);
    } else {
        // Parent process: wait for child to stop
        waitpid(child, NULL, 0);

        // Attach to the child process
        ptrace(PTRACE_ATTACH, child, NULL, NULL);
        waitpid(child, NULL, 0);

        // Modify registers and stack here
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child, NULL, &regs);

        // Assume you have the stack pointer and instruction pointer from the dump
        regs.rsp = new_stack_pointer_from_dump;
        regs.rip = new_instruction_pointer_from_dump;
        
        // Restore stack content (example, highly simplified)
        for (int i = 0; i < stack_size; i += sizeof(long)) {
            long data = *(long *)(stack_dump + i);
            ptrace(PTRACE_POKEDATA, child, (void *)(new_stack_pointer_from_dump + i), data);
        }

        // Apply the modified registers
        ptrace(PTRACE_SETREGS, child, NULL, &regs);

        // Continue the process
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        waitpid(child, NULL, 0);
    }
    return 0;
}
