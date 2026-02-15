#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <termios.h>
#include <unistd.h>

#define SALT_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE 16
#define BLOCK_SIZE 4096
#define ITERATIONS 100000
#define MAX_ATTEMPTS 5

//for encryption..
int encrypt(
    const char* input_file, 
    const char* output_file,
    const char *password
);

//for decrypton.
int decrypt(
    const char* input_file,
    const char *password
);

//derive the key for user given password
void derive_key(
    const char *password,
    unsigned char *salt,
    unsigned char *key
);

void display_help();

#endif