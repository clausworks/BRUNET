CC=gcc
CFLAGS=-Wall -Werror -std=gnu99
TARGET=a.out
LIBARGS=-lnftables -lfyaml

C_HDR := $(wildcard *.h)
C_SRC := $(wildcard *.c)
C_OBJ := $(patsubst %.c, %.o, $(C_SRC))

all: debug

debug: $(C_SRC) $(C_HDR)
	$(CC) $(CFLAGS) -g $(C_SRC) -o $(TARGET) $(LIBARGS)

release: $(C_SRC) $(C_HDR)
	$(CC) $(CFLAGS) $(C_SRC) -o $(TARGET) $(LIBARGS)

clean:
	rm -vf $(C_OBJ) $(TARGET)

