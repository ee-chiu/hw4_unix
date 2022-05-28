#include"helper.h"

int main(int argc, char* argv[]){
    char* script = calloc(100, sizeof(char));
    char* program = calloc(100, sizeof(char));
    init(argc, argv, script, program);
    int exit = get_command_NOLOADED(program);
    if(exit) return 0;
    int entry_point = load(program);
    if(entry_point < 0) return -1;
    printf("** program '%s' loaded. entry point 0x%x\n", program, entry_point);

    pid_t child = fork();
    if(child < 0) { perror("fork"); return -1; }
    else if(child == 0){
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { perror("TRACEME"); return -1; }
        execlp(program, program, NULL);
    }
    else {
        int wait_status;
        if(waitpid(child, &wait_status, 0) < 0) { perror("waitpid"); return -1; }
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        char* command = calloc(30, sizeof(char));
        while(1){
            printf("sdb> ");
            scanf("%s", command);
            if(!strcmp(command, "exit") || !strcmp(command, "q")) break;
        }
    }
}