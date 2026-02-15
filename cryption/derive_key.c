#include "../header_files/cryption.h"

void derive_key(
    const char *password,
    unsigned char *salt,
    unsigned char *key
){
    PKCS5_PBKDF2_HMAC(
        password,
        strlen(password),
        salt,
        SALT_SIZE,
        ITERATIONS,
        EVP_sha256(),
        KEY_SIZE,
        key
    );
}
