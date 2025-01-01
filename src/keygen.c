#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <unistd.h> /* for getpass on POSIX */

#define OUTPUT_FOLDER "ssh_keys"
#define LOG_FILE "key_generation.log"
#define MAX_PATH 256
#define MAX_LOG_BUFFER 1024
#define PASSWORD_MAX 1024

// Global variables for cleanup
static OQS_KEM *global_kem = NULL;
static uint8_t *global_public_key = NULL;
static uint8_t *global_secret_key = NULL;

// Supported algorithms
const char *supported_algs[] = {"Kyber512", "Kyber768", "Kyber1024", NULL};

/* 
 * Use a more general log function to allow different log levels if desired.
 * e.g.: log_message_with_level("Something happened", "INFO");
 */
void log_message_with_level(const char *message, const char *level) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char timestr[20];
        strftime(timestr, sizeof(timestr), "%Y%m%d_%H%M%S", localtime(&now));
        fprintf(log_file, "[%s] [%s] %s\n", timestr, level, message);
        fclose(log_file);
    }
}

// Convenience macro for INFO-level logging
#define log_message(msg) log_message_with_level((msg), "INFO")

// Print usage and supported algorithms
void print_usage(const char* program_name) {
    printf("Usage: %s [algorithm]\n", program_name);
    printf("Supported algorithms:\n");
    for (int i = 0; supported_algs[i]; i++) {
        printf("  - %s\n", supported_algs[i]);
    }
    printf("Default: Kyber1024\n");
}

// Get a timestamp string in YYYYMMDD_HHMMSS format
void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    strftime(buffer, size, "%Y%m%d_%H%M%S", localtime(&now));
}

// Create filenames for public and private keys with a timestamp
void create_filenames(char *pub_path, char *priv_path, const char *alg_name) {
    char timestamp[20];
    get_timestamp(timestamp, sizeof(timestamp));

    // Check return values for snprintf to detect truncation
    int ret;
    ret = snprintf(pub_path, MAX_PATH, "%s/%s_%s_public.txt",
                   OUTPUT_FOLDER, alg_name, timestamp);
    if (ret < 0 || ret >= MAX_PATH) {
        fprintf(stderr, "Error: Public key path truncated.\n");
        exit(EXIT_FAILURE);
    }

    ret = snprintf(priv_path, MAX_PATH, "%s/%s_%s_private.bin",
                   OUTPUT_FOLDER, alg_name, timestamp);
    if (ret < 0 || ret >= MAX_PATH) {
        fprintf(stderr, "Error: Private key path truncated.\n");
        exit(EXIT_FAILURE);
    }
}

// Ensure the output directory exists and has secure permissions (0700)
int ensure_directory(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0700) == -1) {
            fprintf(stderr, "Error creating directory %s: %s\n", path, strerror(errno));
            return -1;
        }
        printf("Created directory: %s\n", path);
        log_message("Created output directory");
    } else {
        // If directory exists, check/fix permissions
        if ((st.st_mode & 0777) != 0700) {
            fprintf(stderr, "Warning: Directory %s has unsafe permissions\n", path);
            if (chmod(path, 0700) == -1) {
                fprintf(stderr, "Failed to fix directory permissions: %s\n", strerror(errno));
                return -1;
            }
            log_message("Fixed directory permissions");
        }
    }
    return 0;
}

// Base64-encode and write data to file
void write_base64_pubkey(FILE* file, const uint8_t* data, size_t len) {
    BIO *bio = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bufferPtr = NULL;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    if (!b64 || !bio) {
        fprintf(stderr, "Error allocating BIO for base64.\n");
        if (b64) BIO_free(b64);
        if (bio) BIO_free(bio);
        return;
    }

    bio = BIO_push(b64, bio);

    int rc = BIO_write(bio, data, (int)len);
    if (rc <= 0) {
        fprintf(stderr, "Error writing to base64 BIO.\n");
    }
    (void)BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    if (bufferPtr) {
        fprintf(file, "%.*s", (int)bufferPtr->length, bufferPtr->data);
    }

    BIO_free_all(bio);
}

// Encrypt the private key data with a password using AES-256-CBC
// (demonstration only; consider AES-GCM or a standardized envelope format in production)
int encrypt_private_key(const uint8_t *key_data, size_t key_length,
                        const char *password, FILE *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_new failed.\n");
        return -1;
    }

    unsigned char salt[8], key[32], iv[16];
    unsigned char *enc_key = malloc(key_length + EVP_MAX_BLOCK_LENGTH);
    if (!enc_key) {
        fprintf(stderr, "Error: Memory allocation failed for enc_key.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Generate random salt
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        fprintf(stderr, "Error: Failed to generate salt.\n");
        free(enc_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Derive key and IV from password+salt
    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt,
                        (unsigned char *)password, (int)strlen(password), 1, key, iv)) {
        fprintf(stderr, "Error: EVP_BytesToKey failed.\n");
        free(enc_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Write 'Salted__' and salt to identify how this file was encrypted
    if (fwrite("Salted__", 1, 8, output) != 8 ||
        fwrite(salt, 1, 8, output) != 8) {
        fprintf(stderr, "Error: Failed to write salt header.\n");
        free(enc_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Encrypt
    int len = 0;
    int enc_len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error: EVP_EncryptInit_ex failed.\n");
        free(enc_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, enc_key, &len, key_data, (int)key_length) != 1) {
        fprintf(stderr, "Error: EVP_EncryptUpdate failed.\n");
        free(enc_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptFinal_ex(ctx, enc_key + len, &enc_len) != 1) {
        fprintf(stderr, "Error: EVP_EncryptFinal_ex failed.\n");
        free(enc_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Write encrypted data
    if (fwrite(enc_key, 1, (size_t)(len + enc_len), output) != (size_t)(len + enc_len)) {
        fprintf(stderr, "Error: Failed to write encrypted key.\n");
        free(enc_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Cleanup
    explicit_bzero(key, sizeof(key));
    explicit_bzero(iv, sizeof(iv));
    explicit_bzero(enc_key, key_length + EVP_MAX_BLOCK_LENGTH);
    free(enc_key);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

// Clean up global structures
void cleanup(void) {
    if (global_secret_key && global_kem) {
        explicit_bzero(global_secret_key, global_kem->length_secret_key);
        free(global_secret_key);
        global_secret_key = NULL;
    }
    if (global_public_key) {
        free(global_public_key);
        global_public_key = NULL;
    }
    if (global_kem) {
        OQS_KEM_free(global_kem);
        global_kem = NULL;
    }
}

// Signal handler using sigaction-compatible signature
static void signal_handler(int signum) {
    char log_buf[100];
    snprintf(log_buf, sizeof(log_buf), "Received signal %d - cleaning up", signum);
    log_message_with_level(log_buf, "WARN");
    cleanup();
    exit(signum);
}

// Helper function to read a line from stdin safely, handling EOF
// On POSIX, we can also use getpass for a non-echo password prompt.
char* safe_fgets(char *buf, size_t size, FILE *stream) {
    if (!fgets(buf, (int)size, stream)) {
        // This could be EOF or an error
        return NULL;
    }
    buf[strcspn(buf, "\n")] = '\0';
    return buf;
}

// For demonstration, we use getpass (POSIX) for password input.
char* read_password(const char *prompt, char *buffer, size_t buffer_size) {
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    // Use the system's getpass which does not echo the password.
    // getpass is deprecated in some environments, but used here for brevity.
    // In production, consider a more portable solution (termios, etc.).
    printf("%s", prompt);
    fflush(stdout);
    char *pw = getpass("");
    if (!pw) {
        fprintf(stderr, "Error: getpass failed.\n");
        return NULL;
    }
    strncpy(buffer, pw, buffer_size - 1);
    buffer[buffer_size - 1] = '\0';
    return buffer;
#else
    // Fallback if getpass isn't available
    printf("%s", prompt);
    fflush(stdout);
    return safe_fgets(buffer, buffer_size, stdin);
#endif
}

int main(int argc, char *argv[]) {
    char pub_path[MAX_PATH];
    char priv_path[MAX_PATH];
    const char *alg_name = "Kyber1024";
    char log_buffer[MAX_LOG_BUFFER];
    char password[PASSWORD_MAX] = {0};
    char verify[PASSWORD_MAX] = {0};

    // Use sigaction instead of signal for better portability and control
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Help menu
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    // Algorithm selection
    if (argc > 1) {
        alg_name = argv[1];
        int valid_alg = 0;
        for (int i = 0; supported_algs[i]; i++) {
            if (strcmp(alg_name, supported_algs[i]) == 0) {
                valid_alg = 1;
                break;
            }
        }
        if (!valid_alg) {
            fprintf(stderr, "Error: Unsupported algorithm %s\n", alg_name);
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    printf("Post-Quantum Key Generator\n");
    printf("--------------------------\n");

    snprintf(log_buffer, MAX_LOG_BUFFER, "Starting key generation with algorithm: %s", alg_name);
    log_message(log_buffer);

    // Ensure output directory exists
    if (ensure_directory(OUTPUT_FOLDER) != 0) {
        log_message_with_level("Failed to ensure output directory", "ERROR");
        return EXIT_FAILURE;
    }

    // Create filenames for pub/priv
    create_filenames(pub_path, priv_path, alg_name);

    printf("Using KEM algorithm: %s\n", alg_name);

    global_kem = OQS_KEM_new(alg_name);
    if (!global_kem) {
        fprintf(stderr, "Error: Failed to initialize KEM algorithm: %s\n", alg_name);
        log_message_with_level("Failed to initialize KEM algorithm", "ERROR");
        return EXIT_FAILURE;
    }

    printf("Key lengths - Public: %zu bytes, Private: %zu bytes\n",
           global_kem->length_public_key, global_kem->length_secret_key);

    global_public_key = malloc(global_kem->length_public_key);
    global_secret_key = malloc(global_kem->length_secret_key);
    if (!global_public_key || !global_secret_key) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        log_message_with_level("Memory allocation failed", "ERROR");
        cleanup();
        return EXIT_FAILURE;
    }

    // Generate key pair
    if (OQS_KEM_keypair(global_kem, global_public_key, global_secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error: Keypair generation failed\n");
        log_message_with_level("Keypair generation failed", "ERROR");
        cleanup();
        return EXIT_FAILURE;
    }

    printf("Successfully generated keypair\n");
    log_message("Successfully generated keypair");

    // Write public key (hex + base64) to file
    FILE *pub_file = fopen(pub_path, "w");
    if (!pub_file) {
        fprintf(stderr, "Error: Cannot open public key file: %s\n", strerror(errno));
        log_message_with_level("Failed to open public key file", "ERROR");
        cleanup();
        return EXIT_FAILURE;
    }

    // Hex format
    fprintf(pub_file, "# Hex format:\n");
    for (size_t i = 0; i < global_kem->length_public_key; i++) {
        fprintf(pub_file, "%02x", global_public_key[i]);
    }
    fprintf(pub_file, "\n\n# Base64 format:\n");
    write_base64_pubkey(pub_file, global_public_key, global_kem->length_public_key);

    fclose(pub_file);

    // Secure permissions for public key (0644) or environment-appropriate
    if (chmod(pub_path, 0644) == -1) {
        fprintf(stderr, "Warning: Failed to set public key file permissions\n");
        log_message_with_level("Failed to set public key permissions", "WARN");
    }
    printf("Public key saved to: %s\n", pub_path);

    // Write private key (with optional encryption)
    FILE *priv_file = fopen(priv_path, "wb");
    if (!priv_file) {
        fprintf(stderr, "Error: Cannot open private key file: %s\n", strerror(errno));
        log_message_with_level("Failed to open private key file", "ERROR");
        cleanup();
        return EXIT_FAILURE;
    }

    // Read password (non-echo if possible) for encryption
    if (!read_password("Enter password to encrypt private key (leave blank for no encryption): ",
                       password, sizeof(password))) {
        fprintf(stderr, "Error: Failed to read password.\n");
        fclose(priv_file);
        cleanup();
        return EXIT_FAILURE;
    }

    if (strlen(password) > 0) {
        if (!read_password("Verify password: ", verify, sizeof(verify))) {
            fprintf(stderr, "Error: Failed to read verification password.\n");
            fclose(priv_file);
            cleanup();
            return EXIT_FAILURE;
        }

        if (strcmp(password, verify) != 0) {
            fprintf(stderr, "Error: Passwords do not match\n");
            log_message_with_level("Password verification failed", "ERROR");
            fclose(priv_file);
            cleanup();
            return EXIT_FAILURE;
        }

        // Encrypt private key
        if (encrypt_private_key(global_secret_key, global_kem->length_secret_key,
                                password, priv_file) != 0) {
            fprintf(stderr, "Error: Failed to encrypt private key.\n");
            fclose(priv_file);
            cleanup();
            return EXIT_FAILURE;
        }
        log_message("Private key encrypted with password");
    } else {
        // No encryption
        if (fwrite(global_secret_key, 1, global_kem->length_secret_key, priv_file) 
            != global_kem->length_secret_key) {
            fprintf(stderr, "Error: Failed to write private key.\n");
            fclose(priv_file);
            cleanup();
            return EXIT_FAILURE;
        }
        log_message("Private key saved without encryption");
    }

    // Immediately zero out password buffers in memory
    explicit_bzero(password, sizeof(password));
    explicit_bzero(verify, sizeof(verify));

    fclose(priv_file);

    // Secure permissions for private key (0600)
    if (chmod(priv_path, 0600) == -1) {
        fprintf(stderr, "Warning: Failed to set private key file permissions\n");
        log_message_with_level("Failed to set private key permissions", "WARN");
    }
    printf("Private key saved to: %s\n", priv_path);

    snprintf(log_buffer, MAX_LOG_BUFFER,
             "Key generation completed - Public: %s, Private: %s",
             pub_path, priv_path);
    log_message(log_buffer);

    cleanup();
    printf("\nKey generation completed successfully!\n");
    return EXIT_SUCCESS;
}

