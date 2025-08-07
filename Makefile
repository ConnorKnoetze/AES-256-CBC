# Compiler and flags
CC = g++
CFLAGS = -g -Wall -fdiagnostics-color=always

# Paths to OpenSSL libraries and headers
OPENSSL_LIB = /ucrt64/lib
OPENSSL_INCLUDE = /ucrt64/include


# Output binaries
ENCRYPT_TARGET = ./encrypt/encrypt.exe
DECRYPT_TARGET = ./decrypt/decrypt.exe

# Source files
ENCRYPT_SRCS = ./encrypt/encrypt.c
DECRYPT_SRCS = ./decrypt/decrypt.c

encrypt:
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o $(ENCRYPT_TARGET) $(ENCRYPT_SRCS) -lcrypto -lssl

decrypt:
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o $(DECRYPT_TARGET) $(DECRYPT_SRCS) -lcrypto -lssl

# Build target
all: encrypt decrypt

$(ENCRYPT_TARGET): $(ENCRYPT_SRCS)
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o $(ENCRYPT_TARGET) $(ENCRYPT_SRCS) -lcrypto -lssl

$(DECRYPT_TARGET): $(DECRYPT_SRCS)
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o $(DECRYPT_TARGET) $(DECRYPT_SRCS) -lcrypto -lssl

# Test target
test: test.c
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o test.exe test.c -lcrypto -lssl

# Add a target for tester.c
tester: ./decrypt/tester.c
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o ./decrypt/tester.exe ./decrypt/tester.c -lcrypto -lssl

# Clean up
clean:
	rm -f $(TARGET) ./decrypt/decrypt.exe
	rm -f $(TARGET) ./decrypt/tester.exe
	rm -f $(TARGET) ./encrypt/encrypt.exe
