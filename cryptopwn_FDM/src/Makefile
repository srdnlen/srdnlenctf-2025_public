CC = gcc
CFLAGS = -Wall -fstack-protector-all
CLIBS = -lgmp -lcrypto
TARGET_DIR = build
SRC_DIR = src
TARGET = cryptopwn
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(SRC:.c=.o)
# OBJ = $(patsubst $(SRC_DIR)/%.c,$(TARGET_DIR)/%.o,$(SRC))

all: $(TARGET_DIR) $(TARGET)

$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET_DIR)/$(TARGET) $(CLIBS)

$(TARGET_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	echo $(SRC)
	rm -f $($TARGET_DIR)/$(TARGET) $(OBJ)

run: $(TARGET)
	$(TARGET_DIR)/$(TARGET)

debug: CFLAGS += -DDEBUG

debug: clean $(TARGET)

