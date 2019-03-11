/*
** EPITECH PROJECT, 2019
** PSU_strace_2018
** File description:
** proces
*/

#include "strace.h"

int child_func(char **ac, char **env, int flags)
{
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    kill(getpid(), SIGSTOP);
    return (execve(ac[1 + (flags / 10)], ac + (1 + (flags / 10)), env));
}

void next_step(pid_t pid, int *st)
{
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    wait4(pid, st, 0, NULL);
}

void choice_print(char *name, pid_t pid, int flag)
{
    size_t x = 0;
    void (*prints[4])(long int, pid_t) = {&print_void_ptr, &print_int,
                                    &print_char_ptr, &print_size_t};
    char *tab[4] = {"voidptr", "int", "charptr", "size_t"};

    for (size_t i = 1; i <= (size_t)(name[strlen(name) - 1] - 48); i++)
    {
        if (i > 1)
            printf(", ");
        if (flag == 0) {
            prints[0](takeinfo(i, pid), pid);
            continue;
        }
        for (x = 0; x < 4; x++)
            if (strncmp(tab[x],
                    &name[strlen_delim(name, ':', i -1) +1],
                    (strlen_delim(name, ':', i) - 1) -
                    (strlen_delim(name, ':', i - 1) +1))==0)
                break;
        if (x == 4)
            prints[0](takeinfo(i, pid), pid);
        else
            prints[x](takeinfo(i, pid), pid);
    }
}

void tracer(char **name, pid_t pid, int *st, int flags)
{
    long int ret;

    wait4(pid, st, 0, NULL);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
    ptrace(PTRACE_ATTACH, pid, 0, 0);
    while (1) {
        next_step(pid, st);
        if (WIFEXITED(*st))
            break;
        if ((ret = ptrace(PTRACE_PEEKUSER, pid,
                    sizeof(long) * ORIG_RAX, 0)) != -1) {
            strace_print(name[ret], pid, flags);
            next_step(pid, st);
            if (flags / 10 == 0)
                print_void_ptr(takeinfo(0, pid), pid);
            else
                print_int(takeinfo(0, pid), pid);
            printf("\n");
        }
    }
}
