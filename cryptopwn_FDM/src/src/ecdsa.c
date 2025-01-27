#include "ecdsa.h"

void bytes_to_hex(const unsigned char *byte_array, size_t length, char *hex_str) {
    for (size_t i = 0; i < length; i++)
        sprintf(&hex_str[i * 2], "%02X", byte_array[i]);
    hex_str[length * 2] = '\0';
}
void hex_to_bytes(const char *hex_str, size_t byte_array_size, unsigned char *byte_array) {
    size_t len = strlen(hex_str);
    assert(!(len % 2 != 0 || byte_array_size < len / 2));
    for (size_t i = 0; i < len; i += 2)
        sscanf(&hex_str[i], "%2hhx", &byte_array[i / 2]);
}

void sha256(mpz_t res, const void* str, size_t len) {
    unsigned char hash[32];
	char hex_hash[2*32+1];

	char* hex_data = malloc(len*2+1);
	bytes_to_hex(str, len, hex_data);

	char* base_command = "echo \"%s\" | xxd -r -p | sha256sum";
	char* command = malloc(strlen(base_command)+len*2+1);
	sprintf(command, base_command, hex_data);

	FILE* fp = popen(command, "r");
	assert(fp != NULL);
	fscanf(fp, "%64s", hex_hash);
	pclose(fp);

#ifdef DEBUG
	printf("hash cmd: %s", command);
#endif

	hex_to_bytes(hex_hash, sizeof(hash), hash);

#ifdef DEBUG
	printf(" hash -> %s <- ", hex_hash);
#endif

    mpz_set_si(res, -1);
    mpz_set_ui(res, 0);
    for (int i = 0; i < 32; i++) {
        mpz_mul_2exp(res, res, 8);
        mpz_add_ui(res, res, hash[i]);
    }
	free(hex_data);
	free(command);
}

void sign_(mpz_t r, mpz_t s, char* msg, size_t len, mpz_t d, Point* G, Curve* curve, int urandom) {
    mpz_t z;
    mpz_init(z);
    sha256(z, msg, len);
    assert(mpz_cmp_si(z, -1) > 0);

    // generate ECDSA random nonce
    mpz_t k, inv_k;
    mpz_init(k);
    mpz_init(inv_k);
    unsigned char rand[32];
    do {
        mpz_set_ui(k, 0);
        read(urandom, rand, 32);
        for (int i = 0; i < 32; i++) {
            for (int j = 7; j >= 0; j--) {
                mpz_mul_ui(k, k, 2);
                mpz_add_ui(k, k, (rand[i] & (1 << j)) >> j);
            }
        }
    } while (mpz_cmp_ui(k, 0) == 0 || mpz_cmp(k, curve->n) >= 0);
    mpz_invert(inv_k, k, curve->n);

    // generate ECDSA signature (r, s)
    Point T = scalar_multiplication(k, G);
    mpz_set(r, T.x);
    assert(mpz_cmp_ui(r, 0) > 0);

    mpz_set(s, d);
    mpz_mul(s, s, r);
    mpz_add(s, s, z);
    mpz_mul(s, s, inv_k);
    mpz_mod(s, s, curve->n);
    assert(mpz_cmp_ui(s, 0) > 0);

    mpz_clear(z);
    mpz_clear(k);
    mpz_clear(inv_k);
    point_clear(&T);
}

void sign(mpz_t* r_arr, mpz_t* s_arr, intptr_t msgs, size_t hashable_size, size_t idx, size_t msgs_count, mpz_t d, Point* G, Curve* curve, int urandom_fd) {
    if (idx == msgs_count) {
        return;
    }

    mpz_t z;
    mpz_init(z);
    sha256(z, (void*)(msgs+idx*hashable_size), hashable_size);
    assert(mpz_cmp_si(z, -1) > 0);


    // generate ECDSA random nonce
    mpz_t k, inv_k;
    mpz_init(k);
    mpz_init(inv_k);
    unsigned char rand[32];
    do {
        mpz_set_ui(k, 0);
        read(urandom_fd, rand, 32);
        for (int i = 0; i < 32; i++) {
            for (int j = 7; j >= 0; j--) {
                mpz_mul_ui(k, k, 2);
                mpz_add_ui(k, k, (rand[i] & (1 << j)) >> j);
            }
        }
    } while (mpz_cmp_ui(k, 0) == 0 || mpz_cmp(k, curve->n) >= 0);
    mpz_invert(inv_k, k, curve->n);


#ifdef DEBUG
	printf("NOW PRINTING NONCE K: ");
	mpz_out_str(stdout, 16, k);
	puts(";");
#endif

    // generate ECDSA signature (r, s)
    Point T = scalar_multiplication(k, G);
    mpz_set(r_arr[idx], T.x);

    assert(mpz_cmp_ui(r_arr[idx], 0) > 0);

    mpz_set(s_arr[idx], d);
    mpz_mul(s_arr[idx], s_arr[idx], r_arr[idx]);
    mpz_add(s_arr[idx], s_arr[idx], z);
    mpz_mul(s_arr[idx], s_arr[idx], inv_k);
    mpz_mod(s_arr[idx], s_arr[idx], curve->n);
    assert(mpz_cmp_ui(s_arr[idx], 0) > 0);

    sign(r_arr, s_arr, msgs, hashable_size, idx+1, msgs_count, d, G, curve, urandom_fd);

    mpz_clear(z);
    mpz_clear(k);
    mpz_clear(inv_k);
    point_clear(&T);
}

bool verify(mpz_t r, mpz_t s, intptr_t msg, size_t len, Point* Q, Point* G, Curve* curve) {
    if (!check_point(Q, curve)) {
        return false;
    }
    if (!(mpz_cmp_ui(r, 0) > 0 && mpz_cmp(r, curve->n) < 0 && mpz_cmp_ui(s, 0) > 0 && mpz_cmp(s, curve->n) < 0)) {
        return false;
    }

    mpz_t z;
    mpz_init(z);
    sha256(z, (void*)msg, len);
    assert(mpz_cmp_si(z, -1) > 0);

    mpz_t w;
    mpz_init(w);
    mpz_invert(w, s, curve->n);

    mpz_t u1, u2;
    mpz_init(u1);
    mpz_init(u2);
    mpz_mul(u1, z, w);
    mpz_mod(u1, u1, curve->n);
    mpz_mul(u2, r, w);
    mpz_mod(u2, u2, curve->n);

    Point uG = scalar_multiplication(u1, G);
    Point uQ = scalar_multiplication(u2, Q);

    Point T;
	mpz_init(T.x);
	mpz_init(T.y);
	point_addition(&uG, &uQ, &T);

    bool res = mpz_cmp(r, T.x) == 0;

    mpz_clear(z);
    mpz_clear(w);
    mpz_clear(u1);
    mpz_clear(u2);
    point_clear(&uG);
    point_clear(&uQ);
    point_clear(&T);

    return res;
}
