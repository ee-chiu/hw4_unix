#include<stdio.h>
#include<string.h>
#include<stdlib.h>

int main(int argc, char* argv[]){
    char* script = calloc(100, sizeof(char));
    char* program = calloc(100, sizeof(char));
    int s_index = -1;
    for(int i = 0; i+1 < argc; i++){
        if(!strcmp(argv[i], "-s")) { strcpy(script, argv[i+1]); s_index = i; break; }
    }
    if(argc == 4){
        if(s_index == 1) strcpy(program, argv[3]);
        else if(s_index == 2) strcpy(program, argv[1]);
    }
}