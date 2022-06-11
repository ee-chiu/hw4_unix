#include"helper.h"

int main(int argc, char* argv[]){
    setvbuf(stdout, NULL, _IONBF, BUFSIZ);
    char* script = calloc(100, sizeof(char));
    char* program = calloc(100, sizeof(char));
    init(argc, argv, script, program);
    FILE* read_file = stdin;
    if(strlen(script) > 0) read_file = fopen(script, "r");
    int exit = get_command_NOLOADED(program, read_file);
    if(exit) return 0;
    uint64_t entry_point = load(program);
    if(entry_point < 0) return -1;
    printf("** program '%s' loaded. entry point 0x%lx\n", program, entry_point);
    get_command(program, read_file);

    return 0;
}