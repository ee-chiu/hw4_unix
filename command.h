#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/ptrace.h>
#include<sys/wait.h>
#include<elf.h>
#include<capstone/capstone.h>
#include<errno.h>
#include<sys/user.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<sys/types.h>
#include<sys/fcntl.h>

#define NOT_LOADED 1
#define LOADED 2 
#define RUNNING 3 

int state = NOT_LOADED;
Elf64_Ehdr elf_header;
Elf64_Shdr section_header;
csh handle = 0;

#define PEEKSIZE 8

typedef struct node node;
typedef struct list list;

struct node {
    int id;
    uint64_t ori_data;
    struct node* next;
} ;

struct list {
    struct node* head;
    struct node* tail;
    int num_points;
} ;

struct list point_list;
int list_used = 0;

void push_back(uint64_t data) {
    struct node* new_node = calloc(1, sizeof(struct node));
    if(!list_used) { point_list.head = new_node; point_list.tail = new_node; point_list.num_points = 1; list_used = 1;}
    new_node->id = point_list.num_points - 1;
    new_node->ori_data = data;
    new_node->next = NULL;

    point_list.tail->next = new_node;
    point_list.num_points++;
    point_list.tail = new_node;
    return;
}

void break_(char* line, pid_t child) {
    char* save_ptr = NULL;
    char* addr = strtok_r(line, " \n", &save_ptr);
    addr = strtok_r(NULL, " \n", &save_ptr);
    if(addr == NULL) { printf("** no address is given\n"); return; }
    if(state != RUNNING) { printf("** state must be RUNNING\n"); return; }

    uint64_t addr_;
    if(addr[1] == 'x') sscanf(addr, "0x%lx", &addr_);
    else sscanf(addr, "%lx", &addr_);
    if(addr_ < elf_header.e_entry) { printf("** the address is out of the range of the text segment"); return; }

    uint64_t data = ptrace(PTRACE_PEEKTEXT, child, addr_, 0);
    push_back(data);

    if(ptrace(PTRACE_POKETEXT, child, addr_, (data & 0xffffffffffffff00) | 0xcc) != 0) { perror("POKETEXT"); return; }   

    return;
} 

void cont(pid_t child) {
    if(state != RUNNING) { printf("** state must be RUNNING\n"); return; }
    int wait_status;
    ptrace(PTRACE_CONT, child, 0, 0);
    if(waitpid(child, &wait_status, 0) < 0) { perror("waitpid"); return; }
    if(WIFEXITED(wait_status)) {
        printf("** child process %d terminiated normally (code %d)\n", child, WEXITSTATUS(wait_status));
        state = LOADED;
    }
    return;
}

void delete() {
    return;
}

uint64_t get_text_size(char* program) {
    int fd = open(program, O_RDONLY);

    /* map ELF file into memory for easier manipulation */
    struct stat statbuf;
    fstat(fd, &statbuf);
    char *fbase = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)fbase;
    Elf64_Shdr *sects = (Elf64_Shdr *)(fbase + ehdr->e_shoff);
    int shnum = ehdr->e_shnum;
    int shstrndx = ehdr->e_shstrndx;

    /* get string table index */
    Elf64_Shdr *shstrsect = &sects[shstrndx];
    char *shstrtab = fbase + shstrsect->sh_offset;

    int i;
    for(i = 0; i < shnum; i++) {
        if(!strcmp(shstrtab+sects[i].sh_name, ".text")) return sects[i].sh_size;
    }
    return -1;
}

void disassemble(pid_t child, unsigned long long rip, char* addr, char* program) {
    uint64_t addr_ = -1;
    if(addr[1] == 'x') sscanf(addr, "0x%lx", &addr_);
    else sscanf(addr, "%lx", &addr_);
    if(addr_ < elf_header.e_entry) { printf("** the address is out of the range of the text segment\n"); return; }
    uint64_t text_size = get_text_size(program);
    uint64_t text_end = elf_header.e_entry + text_size;
    char* buf = calloc(text_size, sizeof(char));
    cs_insn *insn;
    uint64_t ptr;
    int count;

    for(ptr = elf_header.e_entry; ptr < text_end; ptr += PEEKSIZE) {
        long long peek;
        errno = 0;
        peek = ptrace(PTRACE_PEEKTEXT, child, ptr, NULL);
        if(errno != 0) break;
        memcpy(&buf[ptr-elf_header.e_entry], &peek, PEEKSIZE);
    }

    count = cs_disasm(handle, (uint8_t*) buf, text_size, elf_header.e_entry, 0, &insn);
    int print_instructions = 0;
    if(count <= 0) { printf("cs_disasm error!\n"); return; }
    for(int i = 0; i < count; i++) {
        if(insn[i].address < addr_) continue;
        if(insn[i].address >= text_end) break;
        printf("\t%lx: ", insn[i].address);
        for(int j = 0; j < insn[i].size; j++) printf("%02x ", insn[i].bytes[j]);
        printf("\t\t");
        printf("%s\t", insn[i].mnemonic);
        printf("%s\n", insn[i].op_str);
        print_instructions++;
        if(print_instructions == 10) break;
    }
    if(print_instructions < 10) printf("** the address is out of the range of the text segment\n");
    cs_free(insn, count);
    free(buf);
    return;
}

void disasm(char* line, char* program) {
    char* save_ptr = NULL;
    char* addr = strtok_r(line, " \n", &save_ptr);
    addr = strtok_r(NULL, " \n", &save_ptr);
    if(addr == NULL) { printf("** no addr is given\n"); return; }
    if(state != RUNNING) { printf("** state must be RUNNING\n"); return; }

    pid_t child = fork();
    if(child < 0) { perror("disasm fork"); return; }
    else if(child == 0) {
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { perror("TRACEME\n"); return; }
        execlp(program, program, NULL);
    }
    else {
        int wait_status;
        if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) { printf("cs_open error\n"); return; }
        if(waitpid(child, &wait_status, 0) < 0) { perror("waitpid"); return; }
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        struct user_regs_struct regs;
        if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) disassemble(child, regs.rip, addr, program);
    } 
    return;
}

void dump() {
    return;
}

void get(char* line, pid_t child) {
    char* save_ptr = NULL;
    char* reg = strtok_r(line, " \n", &save_ptr);
    reg = strtok_r(NULL, " \n", &save_ptr);
    if(reg == NULL) { printf("** no register is given\n"); return; }
    if(state != RUNNING) { printf("** state must be RUNNING\n"); return; }

    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) { perror("GETREGS"); return; }
    if(!strcmp(reg, "rax")) { printf("rax = %lld (0x%llx)\n", regs.rax, regs.rax); return; }
    if(!strcmp(reg, "rbx")) { printf("rbx = %lld (0x%llx)\n", regs.rbx, regs.rbx); return; }
    if(!strcmp(reg, "rcx")) { printf("rcx = %lld (0x%llx)\n", regs.rcx, regs.rcx); return; }
    if(!strcmp(reg, "rdx")) { printf("rdx = %lld (0x%llx)\n", regs.rdx, regs.rdx); return; }
    if(!strcmp(reg, "r8")) { printf("r8 = %lld (0x%llx)\n", regs.r8, regs.r8); return; }
    if(!strcmp(reg, "r9")) { printf("r9 = %lld (0x%llx)\n", regs.r9, regs.r9); return; }
    if(!strcmp(reg, "r10")) { printf("r10 = %lld (0x%llx)\n", regs.r10, regs.r10); return; }
    if(!strcmp(reg, "r11")) { printf("r11 = %lld (0x%llx)\n", regs.r11, regs.r11); return; }
    if(!strcmp(reg, "r12")) { printf("r12 = %lld (0x%llx)\n", regs.r12, regs.r12); return; }
    if(!strcmp(reg, "r13")) { printf("r13 = %lld (0x%llx)\n", regs.r13, regs.r13); return; }
    if(!strcmp(reg, "r14")) { printf("r14 = %lld (0x%llx)\n", regs.r14, regs.r14); return; }
    if(!strcmp(reg, "r15")) { printf("r15 = %lld (0x%llx)\n", regs.r15, regs.r15); return; }
    if(!strcmp(reg, "rdi")) { printf("rdi = %lld (0x%llx)\n", regs.rdi, regs.rdi); return; }
    if(!strcmp(reg, "rsi")) { printf("rsi = %lld (0x%llx)\n", regs.rsi, regs.rsi); return; }
    if(!strcmp(reg, "rbp")) { printf("rbp = %lld (0x%llx)\n", regs.rbp, regs.rbp); return; }
    if(!strcmp(reg, "rsp")) { printf("rsp = %lld (0x%llx)\n", regs.rsp, regs.rsp); return; }
    if(!strcmp(reg, "rip")) { printf("rip = %lld (0x%llx)\n", regs.rip, regs.rip); return; }
    if(!strcmp(reg, "flags")) { printf("flags = %lld (0x%llx)\n", regs.eflags, regs.eflags); return; }

    return;
}

void getregs(pid_t child) {
    if(state != RUNNING) { printf("** state must be RUNNING\n"); return; }
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) { perror("GETREGS"); return; }
    printf("RAX %llx\t\tRBX %llx\t\tRCX %llx\t\tRDX %llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
    printf("R8 %llx\t\tR9 %llx\t\tR10 %llx\t\tR11 %llx\n", regs.r8, regs.r9, regs.r10, regs.r11);
    printf("R12 %llx\t\tR13 %llx\t\tR14 %llx\t\tR15 %llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
    printf("RDI %llx\t\tRSI %llx\t\tRBP %llx\t\tRSP %llx\n", regs.rdi, regs.rsi, regs.rbp, regs.rsp);
    printf("RIP %llx\t\t\tFLAGS %016llx\n", regs.rip, regs.eflags);

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

void list_() {
    return;
}

uint64_t load(char* program) {
    FILE* file = fopen(program, "rb");
    if(!file) { perror("fopen"); return -1; }
    fread(&elf_header, sizeof(elf_header), 1, file);
    fclose(file);
    return elf_header.e_entry;
}

void run(char* program, pid_t child) {
    if(state != LOADED && state != RUNNING) { printf("** state must be LOADED or RUNNING\n"); return; }
    int wait_status;
    if(state == RUNNING) {
        printf("** program %s is already running\n", program);
        ptrace(PTRACE_CONT, child, 0, 0);
        if(waitpid(child, &wait_status, 0) < 0) { perror("waitpid"); return; }
        if(WIFEXITED(wait_status)) {
            printf("** child process %d terminiated normally (code %d)\n", child, WEXITSTATUS(wait_status));
            state = LOADED;
        }
        return;
    }

    child = fork();
    if(child < 0) { perror("fork"); return; }
    if(child == 0) {
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { perror("TRACEME"); return; }
        execlp(program, program, NULL);
    }
    else {
        if(waitpid(child, &wait_status, 0) < 0) { perror("waitpid"); return; }
        if(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL) < 0) { perror("SETOPTIONS"); return; }
        state = RUNNING;
        printf("** pid %d\n", child);
        ptrace(PTRACE_CONT, child, 0, 0);
        if(waitpid(child, &wait_status, 0) < 0) { perror("waitpid"); return; }
        if(WIFEXITED(wait_status)) {
            printf("** child process %d terminiated normally (code %d)\n", child, WEXITSTATUS(wait_status));
            state = LOADED;
        }
    }
    return;
}

void vmmap() {
    return;
}

void set(char* line, pid_t child) {
    char* save_ptr = NULL;
    strtok_r(line, " \n", &save_ptr);
    char* reg = strtok_r(NULL, " \n", &save_ptr);
    if(reg == NULL) { printf("** Not enough input arguments\n"); return; }
    char* value_ = strtok_r(NULL, " \n", &save_ptr);
    if(value_ == NULL) { printf("** Not enough input arguments\n"); return; }
    uint64_t value = -1;
    if(value_[1] == 'x') sscanf(value_, "0x%lx", &value);
    else sscanf(value_, "%lx", &value);
    if(state != RUNNING) { printf("** state must be RUNNING\n"); return; }

    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) { perror("GETREGS"); return; }
    if(!strcmp(reg, "rax")) regs.rax = value; 
    if(!strcmp(reg, "rbx")) regs.rbx = value; 
    if(!strcmp(reg, "rcx")) regs.rcx = value; 
    if(!strcmp(reg, "rdx")) regs.rdx = value; 
    if(!strcmp(reg, "r8")) regs.r8 = value; 
    if(!strcmp(reg, "r9")) regs.r9 = value; 
    if(!strcmp(reg, "r10")) regs.r10 = value; 
    if(!strcmp(reg, "r11")) regs.r11 = value; 
    if(!strcmp(reg, "r12")) regs.r12 = value; 
    if(!strcmp(reg, "r13")) regs.r13 = value; 
    if(!strcmp(reg, "r14")) regs.r14 = value; 
    if(!strcmp(reg, "r15")) regs.r15 = value; 
    if(!strcmp(reg, "rdi")) regs.rdi = value; 
    if(!strcmp(reg, "rsi")) regs.rsi = value; 
    if(!strcmp(reg, "rbp")) regs.rbp = value; 
    if(!strcmp(reg, "rsp")) regs.rsp = value; 
    if(!strcmp(reg, "rip")) regs.rip = value; 
    if(!strcmp(reg, "flags")) regs.eflags = value; 

    if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) { perror("GETREGS"); return; }
    return;
}

void si(pid_t child) {
    if(state != RUNNING) { printf("** state must be RUNNING\n"); return; }
    int wait_status;
    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) { perror("SINGLESTEP"); return; }
    if(waitpid(child, &wait_status, 0) < 0) { perror("waitpid"); return; }
    if(WIFEXITED(wait_status)) { 
        printf("** child process %d terminiated normally (code %d)\n", child, WEXITSTATUS(wait_status));
        state = LOADED;
        return; 
    }
    return;
}

pid_t start(char* program) {
    if(state != LOADED) { printf("** state must be LOADED\n"); return -1; }
    pid_t child = fork();
    if(child < 0) { perror("fork"); return -1; }
    else if(child == 0) {
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { perror("TRACEME"); return -1; }
        execlp(program, program, NULL);
    }
    else {
        int wait_status;
        if(waitpid(child, &wait_status, 0) < 0) { perror("waitpid"); return -1; }
        if(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL) < 0) { perror("SETOPTIONS"); return -1; }
        state = RUNNING;
        printf("** pid %d\n", child);
        return child;
    }
    return -1;
}