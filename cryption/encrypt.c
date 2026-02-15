#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "../header_files/cryption.h"
#include "../header_files/storage.h"

#define PATH_SIZE 256

int encrypt(const char *infile, const char *outfile, const char *password) {
    int ret = 0;
    if (!infile || !outfile || !password || strlen(password) == 0) {
        printf("Invalid parameters\n");
        return 0;
    }

    char dest[PATH_SIZE];
    build_encrypted_path(dest, outfile);
    printf("Encrypted file will be saved as: %s\n", dest);

    FILE *in = fopen(infile, "rb");
    FILE *out = fopen(dest, "wb");
    if (!in || !out) {
        printf("File error\n");
        if (in) fclose(in);
        if (out) fclose(out);
        return 0;
    }

    unsigned char salt[SALT_SIZE], key[KEY_SIZE], iv[IV_SIZE];

    if (!RAND_bytes(salt, SALT_SIZE) || !RAND_bytes(iv, IV_SIZE)) {
        printf("Failed to generate random bytes\n");
        fclose(in); fclose(out);
        return 0;
    }

    derive_key(password, salt, key);

    //write salt and IV to the encrypted file
    fwrite(salt, 1, SALT_SIZE, out);
    fwrite(iv, 1, IV_SIZE, out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        printf("Failed to create cipher context\n");
        fclose(in); fclose(out);
        return 0;
    }

    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
        printf("EncryptInit failed\n");
        goto cleanup;
    }

    unsigned char buffer[BLOCK_SIZE];
    unsigned char outbuf[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int n, outlen;

    while((n = fread(buffer, 1, BLOCK_SIZE, in)) > 0){
        if(!EVP_EncryptUpdate(ctx, outbuf, &outlen, buffer, n)){
            printf("EncryptUpdate failed\n");
            goto cleanup;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if(ferror(in)){
        printf("File read error\n");
        goto cleanup;
    }

    if(!EVP_EncryptFinal_ex(ctx, outbuf, &outlen)){
        printf("EncryptFinal failed\n");
        goto cleanup;
    }

    fwrite(outbuf, 1, outlen, out);
    write_metadata(dest, infile, 5);
    ret = 1;

    // Prompt for secure deletion of original file
    char response[10];
    printf("Encryption successful. Do you want to securely delete the original file '%s'? (y/N): ", infile);
    if (fgets(response, sizeof(response), stdin) != NULL && (strcmp(response, "y\n") == 0 || strcmp(response, "Y\n") == 0)) {
        secure_delete_file(infile);
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (in) fclose(in);
    if (out) fclose(out);

    return ret;
}
