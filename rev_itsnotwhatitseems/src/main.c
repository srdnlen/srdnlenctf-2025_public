#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#define AES_BLOCK_SIZE 16

int main() {
    
    // Key and IV (Initialization Vector) for AES 256-bit CBC
    unsigned char key[32];  // 256-bit key
    unsigned char iv[AES_BLOCK_SIZE];  // 128-bit IV
    
    // Generate random key and IV
    if (!RAND_bytes(key, sizeof(key))) {
        fprintf(stderr, "Error generating random key.\n");
        return 1;
    }
    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Error generating random IV.\n");
        return 1;
    }


    // Input plaintext
    char plaintext[1024];
    printf("FLAG: ");
    fgets(plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn(plaintext, "\n")] = '\0';  // Remove trailing newline
    uint8_t xor_keys[38] = {
        51, 50, 36, 46, 44, 37, 46, 59, 46, 115, 54, 115,
        50, 31, 52, 50, 53, 117, 52, 31, 20, 40, 115, 31,
        45, 116, 113, 46, 31, 38, 53, 46, 35, 52, 113, 112, 46, 61
    };
    
    // Prepare ciphertext buffer
    unsigned char ciphertext[1024];
    int ciphertext_len = 0;

    // Initialize OpenSSL context for AES CBC
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating context.\n");
        return 1;
    }
    
    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error initializing encryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    int len = 0;
    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext, strlen(plaintext)) != 1) {
        fprintf(stderr, "Error during encryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    ciphertext_len += len;

    // Finalize encryption (handle padding)
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "Error finalizing encryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    ciphertext_len += len;

    // Free context
    EVP_CIPHER_CTX_free(ctx);

    if (ciphertext == plaintext) {
        puts("Correct!");
    }else {
        printf("Nope!\n");
    }
    

    return 0;
}
