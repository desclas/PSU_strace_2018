/*
** EPITECH PROJECT, 2019
** PSU_strace_2018
** File description:
** utils
*/

#include "strace.h"

size_t strlen_delim(char *str, char delim, size_t nb)
{
    size_t count = 0;
    size_t i = 0;

    for (;str[i] != '\0';i++)
        if (str[i] == delim) {
            count++;
            if (count > nb)
                break;
        }
    return (i);
}
