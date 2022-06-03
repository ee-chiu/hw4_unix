#include "command.h"

void init(const int argc, char* argv[], char* script, char* program) {
    if(argc == 1) return;
    if(argc == 2){ strcpy(program, argv[1]); state = LOADED; return; }
    if(argc == 3){ strcpy(script, argv[2]); return; }
    int s_index = -1;
    for(int i = 0; i+1 < argc; i++){
        if(!strcmp(argv[i], "-s")) { strcpy(script, argv[i+1]); s_index = i; break; }
    }
    if(s_index == 1) { strcpy(program, argv[3]); state = LOADED; }
    else if(s_index == 2) { strcpy(program, argv[1]); state = LOADED; }
    return;
}

int get_command_NOLOADED(char* program){
    char* line = (char*) calloc(30, sizeof(char));
    char* line_cpy = (char*) calloc(30, sizeof(char));
    char* save_ptr = NULL;
    while(state == NOT_LOADED){
        printf("sdb> ");
        fgets(line, 30, stdin);
        strcpy(line_cpy, line);
        char* command = strtok_r(line_cpy, " \n", &save_ptr); 
        if(!strcmp(command, "break") || !strcmp(command, "b")) printf("** no address is given\n");
        if(!strcmp(command, "cont") || !strcmp(command, "c")) printf("** state must be RUNNING\n"); 
        if(!strcmp(command, "delete")) printf("** no break-point-id is given\n");
        if(!strcmp(command, "disasm") || !strcmp(command, "d")) disasm(line, NULL); 
        if(!strcmp(command, "dump") || !strcmp(command, "x")) printf("** no addr is given\n");
        if(!strcmp(command, "exit") || !strcmp(command, "q")) return 1;
        if(!strcmp(command, "get") || !strcmp(command, "g")) printf("** no register is given\n");
        if(!strcmp(command, "getregs")) printf("** state must be RUNNING\n");
        if(!strcmp(command, "help") || !strcmp(command, "h")) help();
        if(!strcmp(command, "list") || !strcmp(command, "l")) continue;
        if(!strcmp(command, "load")) { scanf("%s", program); state = LOADED; break; }
        if(!strcmp(command, "run") || !strcmp(command, "r")) printf("** state must be LOADED or RUNNING\n");
        if(!strcmp(command, "vmmap") || !strcmp(command, "m")) printf("** state must be RUNNING\n");
        if(!strcmp(command, "set") || !strcmp(command, "s")) printf("** Not enough input arguments\n");
        if(!strcmp(command, "si")) printf("** state must be RUNNING\n");
        if(!strcmp(command, "start")) printf("** state must be LOADED\n");
    }
    free(line);
    free(line_cpy);
    return 0;
} 

void get_command(char* program) {
    char* line = calloc(30, sizeof(char));
    char* line_cpy = calloc(30, sizeof(char));
    char* save_ptr = NULL;
    pid_t child;
    while(1){
        printf("sdb> ");
        fgets(line, 30, stdin);
        strcpy(line_cpy, line);
        char* command = strtok_r(line_cpy, " \n", &save_ptr);
        if(!strcmp(command, "disasm") || !strcmp(command, "d")) disasm(line, program);
        if(!strcmp(command, "exit") || !strcmp(command, "q")) break;
        if(!strcmp(command, "getregs")) getregs(child);
        if(!strcmp(command, "help") || !strcmp(command, "h")) help();
        if(!strcmp(command, "load")) { printf("** state must be NOT LOADED\n"); continue; }
        if(!strcmp(command, "si")) si(child);
        if(!strcmp(command, "start")) child = start(program);
    }
    free(line);
    free(line_cpy);
}