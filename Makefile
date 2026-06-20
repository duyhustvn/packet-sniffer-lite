CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -g
CPPFLAGS ?= -Isrc
LDFLAGS ?=

BIN := packet-sniffer-lite
TEST_BIN := test_parsers
BUILD_DIR := build/make
OBJ_DIR := $(BUILD_DIR)/obj
SRC := \
	src/main.c \
	src/packet_parser.c \
	src/http_parser.c \
	src/tls_sni_parser.c
OBJ := $(SRC:%.c=$(OBJ_DIR)/%.o)
TEST_OBJ := \
	$(OBJ_DIR)/tests/test_parsers.o \
	$(OBJ_DIR)/src/http_parser.o \
	$(OBJ_DIR)/src/tls_sni_parser.o
BIN_PATH := $(BUILD_DIR)/$(BIN)
TEST_BIN_PATH := $(BUILD_DIR)/$(TEST_BIN)

.PHONY: all clean test

all: $(BIN_PATH)

$(BIN_PATH): $(OBJ)
	@mkdir -p $(@D)
	$(CC) $(OBJ) $(LDFLAGS) -o $@

$(TEST_BIN_PATH): $(TEST_OBJ)
	@mkdir -p $(@D)
	$(CC) $(TEST_OBJ) $(LDFLAGS) -o $@

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

test: $(TEST_BIN_PATH)
	./$(TEST_BIN_PATH)

clean:
	$(RM) -r $(BUILD_DIR)
