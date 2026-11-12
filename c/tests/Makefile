CC ?= gcc
CFLAGS ?= -std=c99 -Wall -Wextra -Werror
BUILD_DIR := build
TEST_BIN := $(BUILD_DIR)/test_helpers

.PHONY: test clean

test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): test_helpers.c ../srs_helpers.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I.. test_helpers.c -o $(TEST_BIN)

clean:
	rmdir $(BUILD_DIR) 2>/dev/null || true
	rm -f $(TEST_BIN)
