#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/ptrace.h>
#include<sys/wait.h>
#include<elf.h>

#define NOT_LOADED 1
#define LOADED 2 
#define RUNNING 3 

int state = NOT_LOADED;

void break_() {
    return;
} 

void cont() {
    return;
}

void delete() {
    return;
}

void disasm() {
    return;
}

void dump() {
    return;
}

void get() {
    return;
}

void getregs() {
    return;
}

void help() {
    printf("- break {instruction-address}: add a break point\n");
    printf("- cont: continue execution\n");
    printf("- delete {break-point-id}: remove a break point\n");
    printf("- disasm addr: disassemble instructions in a file or a memory region\n");
    printf("- dump addr: dump memory content\n");
    printf("- exit: terminate the debugger\n");
    printf("- get reg: get a single value from a register\n");
    printf("- getregs: show registers\n");
    printf("- help: show this message\n");
    printf("- list: list break points\n");
    printf("- load {path/to/a/program}: load a program\n");
    printf("- run: run the program\n");
    printf("- vmmap: show memory layout\n");
    printf("- set reg val: get a single value to a register\n");
    printf("- si: step into instruction\n");
    printf("- start: start the program and stop at the first instruction\n");
}

void list() {
    return;
}

int load(char* program) {
    int entry_point = -1;
    FILE* file = fopen(program, "rb");
    if(!file) { perror("fopen"); return -1; }
    if(fseek(file, 24, SEEK_SET) < 0) { perror("fseek"); return -1; }
    fread(&entry_point, 8, 1, file);
    return entry_point;
}

void run() {
    return;
}

void vmmap() {
    return;
}

void set() {
    return;
}

void si() {
    return;
}

void start() {
    return;
}