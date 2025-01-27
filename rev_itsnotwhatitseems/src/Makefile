# Compiler and flags
CC = gcc
AS = as
CFLAGS = -nostartfiles
LDFLAGS = -nostartfiles -lcrypto -lssl

# Source files
C_SRC = main.c
ASM_SRC = start.s

# Object files
C_OBJ = main.o
ASM_OBJ = start.o

# Output binary
OUTPUT = final_binary

# Default target
all: $(OUTPUT)

# Compile C source file
$(C_OBJ): $(C_SRC)
	$(CC) -c $(CFLAGS) $(C_SRC) -o $(C_OBJ) 

# Assemble assembly source file
$(ASM_OBJ): $(ASM_SRC)
	$(AS) -o $(ASM_OBJ) $(ASM_SRC)

# Link object files to create the final binary
$(OUTPUT): $(C_OBJ) $(ASM_OBJ)
	$(CC) $(LDFLAGS) $(C_OBJ) $(ASM_OBJ) -o $(OUTPUT)

# Clean up object files and binary
clean:
	rm -f $(C_OBJ) $(ASM_OBJ) $(OUTPUT)

# Run the program
run: $(OUTPUT)
	./$(OUTPUT)

# PHONY targets
.PHONY: all clean run
