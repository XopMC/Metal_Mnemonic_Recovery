#if defined(__METAL_VERSION__)
extern constant const ge25519 REC_ALIGN(16) ge25519_basepoint;
#else
extern REC_DEVICE  const ge25519 REC_ALIGN(16) ge25519_basepoint;
#endif

/*
	d
*/

#if defined(__METAL_VERSION__)
extern constant const bignum25519 REC_ALIGN(16) ge25519_ecd;
#else
extern REC_DEVICE  const bignum25519 REC_ALIGN(16) ge25519_ecd;
#endif

#if defined(__METAL_VERSION__)
extern constant const bignum25519 REC_ALIGN(16) ge25519_ec2d;
#else
extern REC_DEVICE  const bignum25519 REC_ALIGN(16) ge25519_ec2d;
#endif

/*
	sqrt(-1)
*/

#if defined(__METAL_VERSION__)
extern constant const bignum25519 REC_ALIGN(16) ge25519_sqrtneg1;
#else
extern REC_DEVICE  const bignum25519 REC_ALIGN(16) ge25519_sqrtneg1;
#endif

#if defined(__METAL_VERSION__)
extern constant const ge25519_niels REC_ALIGN(16) ge25519_niels_sliding_multiples[32];
#else
extern REC_DEVICE  const ge25519_niels REC_ALIGN(16) ge25519_niels_sliding_multiples[32];
#endif
