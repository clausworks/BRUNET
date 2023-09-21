CC=gcc
CFLAGS=-Wall -Werror -std=gnu99 -D_GNU_SOURCE
TARGET=a.out
LIBARGS=-lnftables -lfyaml

TEST_TARGET=test
TEST_FLAGS=-Wno-unused-variable -Wno-unused-function

C_HDR := $(wildcard *.h)
C_SRC := $(wildcard *.c)
C_OBJ := $(patsubst %.c, %.o, $(C_SRC))

CACHE_FILES := $(wildcard *.cache)


all: debug

debug: $(C_SRC) $(C_HDR)
	$(CC) $(CFLAGS) -g $(C_SRC) -o $(TARGET) $(LIBARGS)

release: $(C_SRC) $(C_HDR)
	$(CC) $(CFLAGS) $(C_SRC) -o $(TARGET) $(LIBARGS)

test: $(C_SRC) $(C_HDR)
	$(CC) $(CFLAGS) -g -D__TEST $(C_SRC) -o $(TEST_TARGET) $(LIBARGS) $(TEST_FLAGS)

clean:
	rm -vf $(C_OBJ) $(TARGET) $(CACHE_FILES)
