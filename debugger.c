#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/ptrace.h>
#include<sys/wait.h>

int main(int argc, char* argv[]){
    char* script = calloc(100, sizeof(char));
    char* program = calloc(100, sizeof(char));
    int s_index = -1;
    int p_index = -1;
    for(int i = 0; i+1 < argc; i++){
        if(!strcmp(argv[i], "-s")) { strcpy(script, argv[i+1]); s_index = i; break; }
    }
    if(argc == 4){
        if(s_index == 1) { strcpy(program, argv[3]); p_index = 3; }
        else if(s_index == 2) { strcpy(program, argv[1]); p_index = 1; }
    }
    pid_t child = fork();
    if(child < 0) { perror("fork"); return -1; }
    else if(child == 0){
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { perror("TRACEME"); return -1; }
        execvp(program, argv + p_index);
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