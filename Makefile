# Compiler and flags
CC = g++
CFLAGS = -g -Wall -fdiagnostics-color=always

# Paths to OpenSSL libraries and headers
OPENSSL_LIB = /ucrt64/lib
OPENSSL_INCLUDE = /ucrt64/include

# Output binary
TARGET = ./encrypt/encrypt.exe

# Source files
SRCS = ./encrypt/encrypt.c
encrypt: 
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o $(TARGET) ./encrypt/encrypt.c -lcrypto -lssl

# Build target
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o $(TARGET) $(SRCS) -lcrypto -lssl

# Test target
test: test.c
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o test.exe test.c -lcrypto -lssl

# Add a target for tester.c
tester: ./decrypt/tester.c
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o ./decrypt/tester.exe ./decrypt/tester.c -lcrypto -lssl

# Clean up
clean:
	rm -f $(TARGET) ./decrypt/tester.exe
	rm -f $(TARGET) ./encrypt/encrypt.exe
