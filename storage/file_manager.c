#include<stdio.h>
#include "../header_files/storage.h"
#include "../header_files/cryption.h"

struct EncryptedFile *head = NULL;

//check storage.h
void build_encrypted_path(
    char *dest, 
    const char *filename
){
    snprintf(dest, 256, "%s%s", ENCRYPTED_DIR, filename);
}

//check storage.h
void build_decrypted_path(
    char *dest,
    const char *filename
){
    snprintf(dest, 256,"%s%s",DECRYPTED_DIR,filename);
}


//check storage.h
void write_metadata(
    const char * encrypted_name,
    const char * original_name,
    int rem_attempts
){
    char meta_file[256];
    snprintf(meta_file, 256, "%s%s", METADATA_LOC, "metadata.dat");
    FILE * out = fopen(meta_file, "a");

    if(!out){
        printf("File error\n");
        return;
    }
    fprintf(out, "%s | %s | %d\n", encrypted_name, original_name, rem_attempts);
    fclose(out);
}

//check storage.h
void load_metadata(){
    char original_name[100];
    char encrypted_name[100];
    int rem_attempts;

    //opening the metdata.dat file;
    char meta_file[256];
    snprintf(meta_file, 256, "%s%s", METADATA_LOC, "metadata.dat");
    FILE * in = fopen(meta_file, "r");
    if(!in){
        return;
    }

    while (fscanf(in, " %99[^|]|%99[^|]|%d\n", encrypted_name, original_name, &rem_attempts) == 3) {
        trim_trailing_spaces(encrypted_name);
        trim_trailing_spaces(original_name);
        struct EncryptedFile * node = create_node(encrypted_name, original_name, rem_attempts);
        insert_node(node);
    }
    
}

//check storage.h
struct EncryptedFile * create_node(
    char * encrypted_name,
    char * original_name,
    int rem_attempts
){
    struct EncryptedFile * node = (struct EncryptedFile * ) malloc(sizeof(struct EncryptedFile));
    strncpy(node->encrypted_name, encrypted_name, sizeof(node->encrypted_name) - 1);
    node->encrypted_name[sizeof(node->encrypted_name) - 1] = '\0';
    strncpy(node->original_name, original_name, sizeof(node->original_name) - 1);
    node->original_name[sizeof(node->original_name) - 1] = '\0';
    node->rem_attempts = rem_attempts;
    node->next = NULL;
    return node;
}

//check storage.h
void insert_node(struct EncryptedFile *new_node) {
    if (head == NULL) {
        head = new_node; 
        return;
    }

    struct EncryptedFile *temp = head;
    while (temp->next != NULL) {
        temp = temp->next;
    }
    temp->next = new_node;
}

//check storage.h
struct EncryptedFile* find_node_by_encrypted(const char *encrypted_name){
    struct EncryptedFile *temp = head;
    while (temp != NULL) {
        if(strcmp(temp->encrypted_name, encrypted_name) == 0){
            return temp;
        }
        temp = temp->next;
    }
    return NULL;
}

void rewrite_metadata(){
    char meta_file[256];
    snprintf(meta_file, 256, "%s%s", METADATA_LOC, "metadata.dat");
    FILE * out = fopen(meta_file, "w"); // Open in write mode to truncate

    if(!out){
        printf("File error: Could not rewrite metadata\n");
        return;
    }

    struct EncryptedFile *current = head;
    while(current != NULL){
        fprintf(out, "%s | %s | %d\n", current->encrypted_name, current->original_name, current->rem_attempts);
        current = current->next;
    }
    fclose(out);
}

void trim_trailing_spaces(char *str) {
    int index;
    // Find the last non-whitespace character
    index = strlen(str) - 1;
    while (index >= 0 && (str[index] == ' ' || str[index] == '\n' || str[index] == '\r')) {
        index--;
    }
    // Null terminate the string at the last non-whitespace character
    str[index + 1] = '\0';
}

// New function to securely delete a file
void secure_delete_file(const char *filepath) {
    FILE *f = NULL;
    long file_size;
    
    printf("Securely deleting file: %s\n", filepath);

    f = fopen(filepath, "r+b"); // Open for reading and writing in binary mode
    if (f == NULL) {
        perror("Error opening file for secure deletion");
        return;
    }

    // Get file size
    fseek(f, 0, SEEK_END);
    file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Overwrite with zeros
    char *zero_buffer = (char *)calloc(file_size, sizeof(char));
    if (zero_buffer == NULL) {
        perror("Error allocating memory for zero buffer");
        fclose(f);
        return;
    }
    fwrite(zero_buffer, 1, file_size, f);
    fflush(f); // Ensure data is written to disk
    free(zero_buffer);

    fclose(f); // Close the file
    
    // Remove the file from the filesystem
    if (remove(filepath) != 0) {
        perror("Error removing file after secure overwrite");
    } else {
        printf("File '%s' securely deleted.\n", filepath);
    }
}

void delete_node(const char *encrypted_name){
    struct EncryptedFile *current = head;
    struct EncryptedFile *prev = NULL;

    while(current != NULL && strcmp(current->encrypted_name, encrypted_name) != 0){
        prev = current;
        current = current->next;
    }

    if(current == NULL){ // Node not found
        return;
    }

    if(prev == NULL){ // Node to be deleted is the head
        head = current->next;
    } else {
        prev->next = current->next;
    }
    free(current);
}

void list_files(){
    if (head == NULL) {
        printf("No encrypted files managed.\n");
        return;
    }

    printf("--- Managed Encrypted Files ---\n");
    printf("%-40s %-40s %-10s\n", "Encrypted Name", "Original Name", "Attempts");
    printf("------------------------------------------------------------------------------------------\n");

    struct EncryptedFile *current = head;
    while(current != NULL){
        printf("%-40s %-40s %-10d\n", 
               current->encrypted_name, 
               current->original_name, 
               current->rem_attempts);
        current = current->next;
    }
    printf("------------------------------------------------------------------------------------------\n");
}