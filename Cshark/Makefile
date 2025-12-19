CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LDFLAGS = -lpcap
TARGET = cshark
OBJDIR = obj

# Source files (flat layout)
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:%.c=$(OBJDIR)/%.o)

# Include directory (current directory for headers)
INCLUDES = -I.

# Default target
all: $(TARGET)

# Create object directory if it doesn't exist
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Build target executable
$(TARGET): $(OBJDIR) $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $(TARGET)
	@echo "Build complete! Run with: sudo ./$(TARGET)"

# Compile source files to object files
$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf $(OBJDIR) $(TARGET)
	@echo "Clean complete!"

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "Installing required dependencies..."
	sudo apt-get update
	sudo apt-get install -y libpcap-dev gcc make

# Run with elevated privileges
run: $(TARGET)
	sudo ./$(TARGET)

# Debug build
debug: CFLAGS += -DDEBUG -g
debug: $(TARGET)

# Check for memory leaks (requires valgrind)
memcheck: $(TARGET)
	sudo valgrind --leak-check=full --track-origins=yes ./$(TARGET)

.PHONY: all clean install-deps run debug memcheck