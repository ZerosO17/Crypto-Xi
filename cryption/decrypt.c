#include <stdio.h>
#include "../header_files/cryption.h"
#include "../header_files/storage.h"

int decrypt(
    const char *infile,
    const char *password
){
    int ret = 0; // Initialize return value to 0 (failure)
    FILE *in = NULL;
    FILE *out = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    char dest_infile[256];
    build_encrypted_path(dest_infile, infile);
    in = fopen(dest_infile, "rb");
    struct EncryptedFile * file_node = find_node_by_encrypted(dest_infile);
    if(file_node == NULL){
        printf("FILE NOT FOUND!!!\n"); // Added newline for better output
        goto cleanup;
    } 

    // Check remaining attempts
    if (file_node->rem_attempts <= 0) {
        printf("No remaining attempts for this file. Deleting metadata entry.\n");
        delete_node(infile);
        rewrite_metadata();
        goto cleanup;
    }

    char dest[256];
    build_decrypted_path(dest, file_node->original_name);
    printf("Decrypted file will be saved as: %s\n", dest);
    out = fopen(dest, "wb");

    if (!in || !out) {
        printf("File error\n");
        goto cleanup;
    }

    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    //read salt + iv
    if (fread(salt, 1, SALT_SIZE, in) != SALT_SIZE) {
        printf("Failed to read salt\n");
        goto cleanup;
    }
    if (fread(iv, 1, IV_SIZE, in) != IV_SIZE) {
        printf("Failed to read IV\n");
        goto cleanup;
    }

    derive_key(password, salt, key);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Failed to create cipher context\n");
        goto cleanup;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        printf("DecryptInit failed\n");
        goto cleanup;
    }

    unsigned char buffer[BLOCK_SIZE];
    unsigned char outbuf[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];

    int n, outlen;

    while ((n = fread(buffer, 1, BLOCK_SIZE, in)) > 0) {
        if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, buffer, n)) {
            printf("DecryptUpdate failed\n");
            goto cleanup;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if (ferror(in)) {
        printf("File read error\n");
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        printf("Wrong password or corrupted file\n");
        file_node->rem_attempts--; // Decrement attempts on failure
        if (file_node->rem_attempts <= 0) {
            printf("No remaining attempts left. Deleting metadata entry.\n");
            delete_node(infile);
        }
        rewrite_metadata(); // Update metadata after decrementing or deleting
        goto cleanup;
    }

    fwrite(outbuf, 1, outlen, out);

    // Reset attempts on successful decryption
    file_node->rem_attempts = MAX_ATTEMPTS;
    rewrite_metadata();

    ret = 1; // Success

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (in) fclose(in);
    if (out) fclose(out);

    return ret;
}


