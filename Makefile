NAME = ft_ping

SRCS = main.c
OBJS = $(SRCS:.c=.o)

CFLAGS = -Wall -Wextra -Werror -Ofast -fsanitize=address -g

all: $(NAME)

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $^

$(NAME): $(OBJS)
	gcc $(CFLAGS) -o $@ $^

clean:
	rm -rf $(OBJS)

fclean: clean
	rm -rf $(NAME)

re: fclean all