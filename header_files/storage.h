#ifndef STORAGE_H
#define STORAGE_H
#define ENCRYPTED_DIR "storage/encrypted/"
#define DECRYPTED_DIR "storage/decrypted/"
#define METADATA_LOC "storage/"


struct EncryptedFile {
    char encrypted_name[100];       
    char original_name[100]; 
    int rem_attempts;
    struct EncryptedFile *next;
};
extern struct EncryptedFile *head;

struct EncryptedFile * create_node(
    char * encrypted_name,
    char * original_name,
    int rem_attempts
);
void insert_node(struct EncryptedFile * node);
struct EncryptedFile* find_node_by_encrypted(const char *encrypted_name);

void build_encrypted_path(
    char *dest, 
    const char *filename
);

void build_decrypted_path(
    char *dest, 
    const char *filename
);

int file_exists(const char *path);
void list_files();

//metadata related parts..
void write_metadata(
    const char * encrypted_name, 
    const char * original_name, 
    int rem_attempts
);

void load_metadata();
void rewrite_metadata();
void delete_node(const char *encrypted_name);
void trim_trailing_spaces(char *str);
void secure_delete_file(const char *filepath);
void list_files();

#endif