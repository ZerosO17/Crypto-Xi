#include "header_files/cryption.h"
#include "header_files/storage.h"

#define SALT_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE 16
#define BLOCK_SIZE 4096
#define ITERATIONS 100000


void getPassword(char* password, int size){
    struct termios old, new;

    //getting the old terminal seeting and setting a new setting to turn of echo..
    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new);

    printf("Enter Passowrd : \n");
    if (fgets(password, size, stdin) == NULL) {
        password[0] = '\0';
    }

    //reverting the old settings..
    tcsetattr(STDIN_FILENO, TCSANOW, &old);

    printf("\n");
        password[strcspn(password, "\n")] = '\0';
    }
    
    void display_help() {
        printf("Crypto-XI: File Encryption/Decryption Utility\n");
        printf("Usage:\n");
        printf("  %s enc <input_file> <output_file> - Encrypts a file.\n", "crypto_xi");
        printf("    <input_file>: The path to the file to be encrypted.\n");
        printf("    <output_file>: The desired name for the encrypted output file (will be saved in storage/encrypted/).\n");
        printf("\n");
        printf("  %s dec <encrypted_file>          - Decrypts an encrypted file.\n", "crypto_xi");
        printf("    <encrypted_file>: The name of the encrypted file (must be present in storage/encrypted/).\n");
        printf("\n");
        printf("  %s ls                          - Lists all managed encrypted files and their metadata.\n", "crypto_xi");
        printf("\n");
        printf("  %s rm <encrypted_file>          - Securely deletes an encrypted file and its metadata.\n", "crypto_xi");
        printf("    <encrypted_file>: The name of the encrypted file to be deleted (must be present in storage/encrypted/).\n");
        printf("\n");
        printf("  %s help                        - Displays this help message.\n", "crypto_xi");
        printf("\n");
        printf("Metadata is stored in 'storage/metadata.dat'.\n");
        printf("Encrypted files are saved in 'storage/encrypted/'.\n");
        printf("Decrypted files are saved in 'storage/decrypted/'.\n");
    }
    
    
    int main(int argc, char *argv[]) {

    //load the meta data;
    load_metadata();

    if (argc == 2 && strcmp(argv[1], "ls") == 0) {
        list_files();
        return 0;
    } else if (argc == 2 && strcmp(argv[1], "help") == 0) {
        display_help();
        return 0;
    } else if (argc == 3 && strcmp(argv[1], "rm") == 0) {
        char encrypted_filepath[256];
        build_encrypted_path(encrypted_filepath, argv[2]);
        struct EncryptedFile *file_node = find_node_by_encrypted(encrypted_filepath);

        if (file_node == NULL) {
            printf("Error: Encrypted file '%s' not found in metadata.\n", argv[2]);
            return 1;
        }

        secure_delete_file(encrypted_filepath);
        delete_node(encrypted_filepath);
        rewrite_metadata();
        printf("Encrypted file '%s' and its metadata have been securely removed.\n", argv[2]);
        return 0;
    }

    if (argc < 3){
        printf("Usage:\n");
        printf("Encrypt: %s enc input output\n", argv[0]);
        printf("Decrypt: %s dec input\n", argv[0]); // Corrected this line
        printf("List:    %s ls\n", argv[0]);
        printf("Remove:  %s rm encrypted_file\n", argv[0]);
        printf("Help:    %s help\n", argv[0]);
        return 1;
    }

    char password[256];
    getPassword(password, 256);

    if (strcmp(argv[1], "enc") == 0) {

        if (encrypt(argv[2], argv[3], password)){
            printf("Encryption successful\n");
        }
            

    }
    else if (strcmp(argv[1], "dec") == 0) {

        if (decrypt(argv[2], password))
            printf("Decryption successful\n");

    }
    else if (strcmp(argv[1], "ls") == 0) {
        list_files();
    }
    else {
        printf("Unknown command\n");
    }

    return 0;
}
