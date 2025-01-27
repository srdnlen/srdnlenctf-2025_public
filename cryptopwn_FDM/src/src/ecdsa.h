#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <gmp.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "elliptic_curves.h"

void bytes_to_hex(const unsigned char *byte_array, size_t length, char *hex_array);
void hex_to_bytes(const char *hex_str, size_t byte_array_size, unsigned char *byte_array);
void sha256(mpz_t res, const void* str, size_t len);
void sign_(mpz_t r, mpz_t s, char* msg, size_t len, mpz_t d, Point* G, Curve* curve, int urandom);
void sign(mpz_t* r_arr, mpz_t* s_arr, intptr_t msgs, size_t hashable_size, size_t idx, size_t msgs_count, mpz_t d, Point* G, Curve* curve, int urandom_fd);
bool verify(mpz_t r, mpz_t s, intptr_t msg, size_t len, Point* Q, Point* G, Curve* curve);

#endif
