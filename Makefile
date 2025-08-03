# Compiler and flags
CC = g++
CFLAGS = -g -Wall -fdiagnostics-color=always

# Paths to OpenSSL libraries and headers
OPENSSL_LIB = /ucrt64/lib
OPENSSL_INCLUDE = /ucrt64/include

# Output binary
TARGET = main.exe

# Source files
SRCS = main.c encrypt.c

main: main.c
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o main main.c -lcrypto -lssl

encrypt: encrypt.c
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o encrypt encrypt.c -lcrypto -lssl

# Build target
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o $(TARGET) $(SRCS) -lcrypto -lssl

# Test target
test: test.c
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o test.exe test.c -lcrypto -lssl

# Clean up
clean:
	rm -f $(TARGET) test.exe
