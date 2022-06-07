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
        if(line[0] == '\n') continue;
        strcpy(line_cpy, line);
        char* command = strtok_r(line_cpy, " \n", &save_ptr); 
        if(!strcmp(command, "break") || !strcmp(command, "b")) break_(line, -1, NULL);
        if(!strcmp(command, "cont") || !strcmp(command, "c")) cont(-1); 
        if(!strcmp(command, "delete")) delete(line, -1);
        if(!strcmp(command, "disasm") || !strcmp(command, "d")) disasm(line, NULL); 
        if(!strcmp(command, "dump") || !strcmp(command, "x")) dump(line, -1);
        if(!strcmp(command, "exit") || !strcmp(command, "q")) return 1;
        if(!strcmp(command, "get") || !strcmp(command, "g")) get(line, -1);
        if(!strcmp(command, "getregs")) getregs(-1);
        if(!strcmp(command, "help") || !strcmp(command, "h")) help();
        if(!strcmp(command, "list") || !strcmp(command, "l")) list_();
        if(!strcmp(command, "load")) { scanf("%s", program); state = LOADED; break; }
        if(!strcmp(command, "run") || !strcmp(command, "r")) run(NULL, NULL);
        if(!strcmp(command, "vmmap") || !strcmp(command, "m")) vmmap(-1);
        if(!strcmp(command, "set") || !strcmp(command, "s")) set(line, -1);
        if(!strcmp(command, "si")) si(-1);
        if(!strcmp(command, "start")) start(NULL);
    }
    free(line);
    free(line_cpy);
    return 0;
} 

void get_command(char* program) {
    char* line = calloc(30, sizeof(char));
    char* line_cpy = calloc(30, sizeof(char));
    char* save_ptr = NULL;
    pid_t child = -1;
    while(1){
        printf("sdb> ");
        fgets(line, 30, stdin);
        if(line[0] == '\n') continue;
        strcpy(line_cpy, line);
        char* command = strtok_r(line_cpy, " \n", &save_ptr);
        if(!strcmp(command, "break") || !strcmp(command, "b")) break_(line, child, program);
        if(!strcmp(command, "cont") || !strcmp(command, "c")) cont(child); 
        if(!strcmp(command, "delete")) delete(line, child);
        if(!strcmp(command, "disasm") || !strcmp(command, "d")) disasm(line, program);
        if(!strcmp(command, "dump") || !strcmp(command, "x")) dump(line, child);
        if(!strcmp(command, "exit") || !strcmp(command, "q")) break;
        if(!strcmp(command, "get") || !strcmp(command, "g")) get(line, child);
        if(!strcmp(command, "getregs")) getregs(child);
        if(!strcmp(command, "help") || !strcmp(command, "h")) help();
        if(!strcmp(command, "list") || !strcmp(command, "l")) list_();
        if(!strcmp(command, "load")) { printf("** state must be NOT LOADED\n"); continue; }
        if(!strcmp(command, "run") || !strcmp(command, "r")) run(program, &child);
        if(!strcmp(command, "vmmap") || !strcmp(command, "m")) vmmap(child);
        if(!strcmp(command, "set") || !strcmp(command, "s")) set(line, child);
        if(!strcmp(command, "si")) si(child);
        if(!strcmp(command, "start")) child = start(program);
    }
    free(line);
    free(line_cpy);
}