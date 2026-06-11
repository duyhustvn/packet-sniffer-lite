CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -g
CPPFLAGS ?= -Iinclude
LDFLAGS ?=

BIN := packet-sniffer-lite
TEST_BIN := test_parsers
SRC := \
	src/main.c \
	src/packet_parser.c \
	src/http_parser.c \
	src/tls_sni_parser.c
OBJ := $(SRC:.c=.o)
TEST_OBJ := \
	tests/test_parsers.o \
	src/http_parser.o \
	src/tls_sni_parser.o

.PHONY: all clean test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o $@

$(TEST_BIN): $(TEST_OBJ)
	$(CC) $(TEST_OBJ) $(LDFLAGS) -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	$(RM) $(OBJ) $(TEST_OBJ) $(BIN) $(TEST_BIN)
