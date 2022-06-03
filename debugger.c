#include"helper.h"

int main(int argc, char* argv[]){
    char* script = calloc(100, sizeof(char));
    char* program = calloc(100, sizeof(char));
    init(argc, argv, script, program);
    int exit = get_command_NOLOADED(program);
    if(exit) return 0;
    uint64_t entry_point = load(program);
    if(entry_point < 0) return -1;
    printf("** program '%s' loaded. entry point 0x%lx\n", program, entry_point);
    get_command(program);

    return 0;
}