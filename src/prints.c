/*
** EPITECH PROJECT, 2019
** PSU_strace_2018
** File description:
** prints
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>

void print_void_ptr(long int i, pid_t pid)
{
    (void)pid;
    printf("void %p", (void *)i);
}

void print_int(long int i, pid_t pid)
{
    (void)pid;
    printf("int %d", (int)i);
}

void print_char_ptr(long int i, pid_t pid)
{
    char str[1000];
    char *tmp = str;
    int stop = 0;
    long long_tmp;

    while (stop != -1 && stop != 124) {
        long_tmp = ptrace(PTRACE_PEEKDATA, pid, i + (stop * 8), NULL);
        memcpy(tmp, &long_tmp, 8);
        for (size_t x = 0; x != 8; x++)
            if (tmp[x] == '\0') {
                stop = -2;
                break;
            }
        tmp += sizeof(long);
        stop++;
    }
    printf("char \"%s\"", str);
}
