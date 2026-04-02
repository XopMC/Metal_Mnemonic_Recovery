#ifndef ED25519_H
#define ED25519_H
#if !defined(__METAL_VERSION__)
#include <cstddef>
#include <cstdint>
#endif
//#include "ed25519-hash-custom.h"


#if defined(__cplusplus)
extern "C" {
#endif
//#include "ed25519-donna.h"

typedef unsigned char ed25519_signature[64];
typedef unsigned char ed25519_public_key[32];
typedef unsigned char ed25519_secret_key[32];

typedef unsigned char curved25519_key[32];


REC_DEVICE void set_scalar();
REC_DEVICE void set_hash();
REC_DEVICE void set_le();
REC_DEVICE void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk);
#if !defined(__METAL_VERSION__)
REC_DEVICE void ed25519_publickey_batch(const uint8_t* __restrict__ sk, uint8_t* __restrict__ pk, int n);
#endif
REC_DEVICE void ed25519_key_to_pub(const ed25519_secret_key sk, ed25519_public_key pk);
#if !defined(__METAL_VERSION__)
REC_DEVICE void ed25519_key_to_pub_batch(const uint8_t* __restrict__ sk, uint8_t* __restrict__ pk, int n);
REC_DEVICE int ed25519_sign_open(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);
REC_DEVICE void ed25519_sign(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);

REC_DEVICE int ed25519_sign_open_batch(const unsigned char **m, size_t *mlen, const unsigned char **pk, const unsigned char **RS, size_t num, int *valid);

REC_DEVICE void ed25519_randombytes_unsafe(void *out, size_t count);
#endif

REC_DEVICE void curved25519_scalarmult_basepoint(curved25519_key pk, const curved25519_key e);

REC_DEVICE void add_modL_from_bytes(uint8_t out32[32], const uint8_t inX[32], const uint8_t inY[32]);

#if defined(__cplusplus)
}
#endif


#endif // ED25519_H
