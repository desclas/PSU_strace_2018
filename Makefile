##
## EPITECH PROJECT, 2018
## Makefile
## File description:
## Makefile
##

SRCDIR	=	src

SRC	=	strace.c	\
		info.c		\
		proces.c	\
		prints.c	\
		utils.c

SRC	:=	$(addprefix $(SRCDIR)/, $(SRC))

OBJ	=	$(SRC:.c=.o)

NAME	=	strace

CFLAGS	=	-Iincludes -W -Wextra -Wall -Werror -g3

all: $(NAME)

$(NAME): $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean all
