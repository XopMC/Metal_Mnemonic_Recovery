#if !defined(__METAL_VERSION__)
#include <cstdint>
#endif

#if defined(__METAL_VERSION__)
#define ED25519_THREAD thread
#define ED25519_THREAD_CONST thread const
#else
#define ED25519_THREAD
#define ED25519_THREAD_CONST const
#endif


/* endian */

REC_DEVICE  inline void U32TO8_LE(ED25519_THREAD unsigned char* p, const uint32_t v);

REC_DEVICE  inline uint32_t U8TO32_LE(ED25519_THREAD_CONST unsigned char* p);
