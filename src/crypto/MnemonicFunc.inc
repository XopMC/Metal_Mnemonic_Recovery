// Author: Mikhail Khoroshavin aka "XopMC"

#include "metal/RecoveryDerivationTypes.h"

#include "third_party/secp256k1/secp256k1.h"
#include "third_party/secp256k1/secp256k1_field.h"
#include "third_party/secp256k1/secp256k1_group.h"
#include "third_party/secp256k1/secp256k1_scalar.h"
#include "third_party/ed25519/ed25519.h"

#if defined(__METAL_VERSION__)
#define MN_THREAD_PTR(T) thread T*
#define MN_THREAD_CONST_PTR(T) thread const T*
#define MN_THREAD_REF(T) thread T&
#define memcpy(dst, src, len) recovery_copy_thread_bytes((thread cmr_u8*)(dst), (const thread cmr_u8*)(src), cmr_u32(len))
#else
#define MN_THREAD_PTR(T) T*
#define MN_THREAD_CONST_PTR(T) const T*
#define MN_THREAD_REF(T) T&
#endif

REC_DEVICE
// hardened_private_child_from_private: performs hardened private child from private.
void hardened_private_child_from_private(MN_THREAD_CONST_PTR(extended_private_key_t) parent, MN_THREAD_PTR(extended_private_key_t) child, uint32_t hardened_child_number) {

	uint32_t hmacsha512_result[16];
	uint8_t hmac_input[40];
	hmac_input[0] = 0;
	memcpy(&hmac_input[1], parent->key, 32);
	hmac_input[33] = (hardened_child_number >> 24) & 0xFF;
	hmac_input[34] = (hardened_child_number >> 16) & 0xFF;
	hmac_input[35] = (hardened_child_number >> 8) & 0xFF;
	hmac_input[36] = hardened_child_number & 0xFF;
	hmac_sha512_const((MN_THREAD_CONST_PTR(uint32_t))parent->chain_code, (MN_THREAD_CONST_PTR(uint32_t))&hmac_input, (MN_THREAD_PTR(uint32_t))hmacsha512_result);
	secp256k1_ec_seckey_tweak_add((MN_THREAD_PTR(uint8_t))hmacsha512_result, (MN_THREAD_CONST_PTR(uint8_t))parent->key);
	memcpy(child->key, hmacsha512_result, 32);
	memcpy(child->chain_code, &hmacsha512_result[8], 32);
}

REC_DEVICE
// hardened_private_child_from_private_precomp: performs hardened private child from private precomp.
void hardened_private_child_from_private_precomp(MN_THREAD_CONST_PTR(extended_private_key_t) parent, MN_THREAD_PTR(extended_private_key_t) child, uint32_t hardened_child_number, MN_THREAD_CONST_PTR(hmac_sha512_precomp_t) hctx) {
	uint8_t hmacsha512_result[64];
	uint8_t hmac_input[40];
	hmac_input[0] = 0;
	memcpy(&hmac_input[1], parent->key, 32);
	hmac_input[33] = (hardened_child_number >> 24) & 0xFF;
	hmac_input[34] = (hardened_child_number >> 16) & 0xFF;
	hmac_input[35] = (hardened_child_number >> 8) & 0xFF;
	hmac_input[36] = hardened_child_number & 0xFF;
	hmac_sha512_const_precomp(hctx, (MN_THREAD_CONST_PTR(uint32_t))hmac_input, (MN_THREAD_PTR(uint32_t))hmacsha512_result);
	secp256k1_ec_seckey_tweak_add(hmacsha512_result, (MN_THREAD_CONST_PTR(uint8_t))parent->key);
	memcpy(child->key, hmacsha512_result, 32);
	memcpy(child->chain_code, hmacsha512_result + 32, 32);
}

REC_DEVICE
// normal_private_child_from_private: performs normal private child from private.
void normal_private_child_from_private(const SECP_CONSTANT secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, MN_THREAD_CONST_PTR(extended_private_key_t) parent, MN_THREAD_PTR(extended_private_key_t) child, uint32_t normal_child_number) {
	uint32_t hmacsha512_result[16];
	extended_public_key_t pub;
	secp256k1_ec_pubkey_create((MN_THREAD_PTR(secp256k1_pubkey))&pub.key, parent->key, precPtr, precPitch);

	uint8_t hmac_input[40];
	serialized_public_key((SECP_THREAD uint8_t*)&pub.key, (SECP_THREAD uint8_t*)&hmac_input);
	hmac_input[33] = (normal_child_number >> 24) & 0xFF;
	hmac_input[34] = (normal_child_number >> 16) & 0xFF;
	hmac_input[35] = (normal_child_number >> 8) & 0xFF;
	hmac_input[36] = normal_child_number & 0xFF;

	hmac_sha512_const((MN_THREAD_CONST_PTR(uint32_t))parent->chain_code, (MN_THREAD_CONST_PTR(uint32_t))&hmac_input, (MN_THREAD_PTR(uint32_t))hmacsha512_result);
	secp256k1_ec_seckey_tweak_add((MN_THREAD_PTR(uint8_t))hmacsha512_result, (MN_THREAD_CONST_PTR(uint8_t))parent->key);
	memcpy(child->key, hmacsha512_result, 32);
	memcpy(child->chain_code, &hmacsha512_result[8], 32);
}

REC_DEVICE
// normal_private_child_from_private_cached_pub: performs normal private child from private cached pub.
void normal_private_child_from_private_cached_pub(MN_THREAD_CONST_PTR(extended_private_key_t) parent, MN_THREAD_PTR(extended_private_key_t) child, uint32_t normal_child_number, MN_THREAD_CONST_PTR(uint8_t) cached_serialized_pub) {
	uint32_t hmacsha512_result[16];
	uint8_t hmac_input[40];
	memcpy(hmac_input, cached_serialized_pub, 33);
	hmac_input[33] = (normal_child_number >> 24) & 0xFF;
	hmac_input[34] = (normal_child_number >> 16) & 0xFF;
	hmac_input[35] = (normal_child_number >> 8) & 0xFF;
	hmac_input[36] = normal_child_number & 0xFF;
	hmac_sha512_const((MN_THREAD_CONST_PTR(uint32_t))parent->chain_code, (MN_THREAD_CONST_PTR(uint32_t))&hmac_input, (MN_THREAD_PTR(uint32_t))hmacsha512_result);
	secp256k1_ec_seckey_tweak_add((MN_THREAD_PTR(uint8_t))hmacsha512_result, (MN_THREAD_CONST_PTR(uint8_t))parent->key);
	memcpy(child->key, hmacsha512_result, 32);
	memcpy(child->chain_code, &hmacsha512_result[8], 32);
}

REC_DEVICE
// normal_private_child_from_private_cached_pub_precomp: performs normal private child from private cached pub precomp.
void normal_private_child_from_private_cached_pub_precomp(MN_THREAD_CONST_PTR(extended_private_key_t) parent, MN_THREAD_PTR(extended_private_key_t) child, uint32_t normal_child_number, MN_THREAD_CONST_PTR(uint8_t) cached_serialized_pub, MN_THREAD_CONST_PTR(hmac_sha512_precomp_t) hctx) {
	uint8_t hmacsha512_result[64];
	uint8_t hmac_input[40];
	memcpy(hmac_input, cached_serialized_pub, 33);
	hmac_input[33] = (normal_child_number >> 24) & 0xFF;
	hmac_input[34] = (normal_child_number >> 16) & 0xFF;
	hmac_input[35] = (normal_child_number >> 8) & 0xFF;
	hmac_input[36] = normal_child_number & 0xFF;
	hmac_sha512_const_precomp(hctx, (MN_THREAD_CONST_PTR(uint32_t))hmac_input, (MN_THREAD_PTR(uint32_t))hmacsha512_result);
	secp256k1_ec_seckey_tweak_add(hmacsha512_result, (MN_THREAD_CONST_PTR(uint8_t))parent->key);
	memcpy(child->key, hmacsha512_result, 32);
	memcpy(child->chain_code, hmacsha512_result + 32, 32);
}

REC_DEVICE
// normal_private_child_from_private_save_pub: saves pub for normal private child from private.
void normal_private_child_from_private_save_pub(const SECP_CONSTANT secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, MN_THREAD_CONST_PTR(extended_private_key_t) parent, MN_THREAD_PTR(extended_private_key_t) child, uint32_t normal_child_number, MN_THREAD_PTR(uint8_t) out_serialized_pub) {
	uint32_t hmacsha512_result[16];
	extended_public_key_t pub;
	secp256k1_ec_pubkey_create((MN_THREAD_PTR(secp256k1_pubkey))&pub.key, parent->key, precPtr, precPitch);

	uint8_t hmac_input[40];
	serialized_public_key((SECP_THREAD uint8_t*)&pub.key, (SECP_THREAD uint8_t*)&hmac_input);
	memcpy(out_serialized_pub, hmac_input, 33);
	hmac_input[33] = (normal_child_number >> 24) & 0xFF;
	hmac_input[34] = (normal_child_number >> 16) & 0xFF;
	hmac_input[35] = (normal_child_number >> 8) & 0xFF;
	hmac_input[36] = normal_child_number & 0xFF;

	hmac_sha512_const((MN_THREAD_CONST_PTR(uint32_t))parent->chain_code, (MN_THREAD_CONST_PTR(uint32_t))&hmac_input, (MN_THREAD_PTR(uint32_t))hmacsha512_result);
	secp256k1_ec_seckey_tweak_add((MN_THREAD_PTR(uint8_t))hmacsha512_result, (MN_THREAD_CONST_PTR(uint8_t))parent->key);
	memcpy(child->key, hmacsha512_result, 32);
	memcpy(child->chain_code, &hmacsha512_result[8], 32);
}

// Device helper: hardened_private_child_from_private_ed25519.
REC_DEVICE  void hardened_private_child_from_private_ed25519(MN_THREAD_CONST_PTR(extended_private_key_t) parent, MN_THREAD_PTR(extended_private_key_t) child, uint32_t hardened_child_number) {
	uint8_t hmacsha512_result[64];
	uint8_t hmac_input[40];
	hmac_input[0] = 0;
	memcpy(&hmac_input[1], parent->key, 32);

	hmac_input[33] = (hardened_child_number >> 24) & 0xFF;
	hmac_input[34] = (hardened_child_number >> 16) & 0xFF;
	hmac_input[35] = (hardened_child_number >> 8) & 0xFF;
	hmac_input[36] = hardened_child_number & 0xFF;
	hmac_sha512_const((MN_THREAD_CONST_PTR(uint32_t))parent->chain_code, (MN_THREAD_CONST_PTR(uint32_t))&hmac_input, (MN_THREAD_PTR(uint32_t))&hmacsha512_result);

	memcpy(child->key, hmacsha512_result, 32);

	memcpy(child->chain_code, hmacsha512_result + 32, 32);
}

// Device helper: hardened_private_child_from_private_ed25519_precomp.
REC_DEVICE  void hardened_private_child_from_private_ed25519_precomp(MN_THREAD_CONST_PTR(extended_private_key_t) parent, MN_THREAD_PTR(extended_private_key_t) child, uint32_t hardened_child_number, MN_THREAD_CONST_PTR(hmac_sha512_precomp_t) hctx) {
	uint8_t hmacsha512_result[64];
	uint8_t hmac_input[40];
	hmac_input[0] = 0;
	memcpy(&hmac_input[1], parent->key, 32);
	hmac_input[33] = (hardened_child_number >> 24) & 0xFF;
	hmac_input[34] = (hardened_child_number >> 16) & 0xFF;
	hmac_input[35] = (hardened_child_number >> 8) & 0xFF;
	hmac_input[36] = hardened_child_number & 0xFF;
	hmac_sha512_const_precomp(hctx, (MN_THREAD_CONST_PTR(uint32_t))hmac_input, (MN_THREAD_PTR(uint32_t))hmacsha512_result);
	memcpy(child->key, hmacsha512_result, 32);
	memcpy(child->chain_code, hmacsha512_result + 32, 32);
}

REC_DEVICE void ed25519_bip32_ckd_priv_hardened(MN_THREAD_CONST_PTR(extended_private_key_t) parent,
	MN_THREAD_PTR(extended_private_key_t) child,
	uint32_t i_hardened)
{
	uint8_t in[1 + 32 + 4];
	uint8_t out64[64];

	in[0] = 0x00;
	memcpy(in + 1, parent->key, 32);
	in[33] = (uint8_t)(i_hardened >> 24);
	in[34] = (uint8_t)(i_hardened >> 16);
	in[35] = (uint8_t)(i_hardened >> 8);
	in[36] = (uint8_t)(i_hardened);

	hmac_sha512_const((MN_THREAD_CONST_PTR(uint32_t))parent->chain_code,
		(MN_THREAD_CONST_PTR(uint32_t))in,
		(MN_THREAD_PTR(uint32_t))out64);

	memcpy(child->key, out64, 32);  // IL
	memcpy(child->chain_code, out64 + 32, 32);  // IR
}

REC_DEVICE void ed25519_bip32_ckd_priv_normal(MN_THREAD_CONST_PTR(extended_private_key_t) parent,
	MN_THREAD_PTR(extended_private_key_t) child,
	uint32_t i_normal)
{
	uint8_t A_par[32];
	ed25519_publickey(parent->key, A_par);

	uint8_t inZ[1 + 32 + 4];
	uint8_t Z64[64];
	inZ[0] = 0x02;
	memcpy(inZ + 1, A_par, 32);
	inZ[33] = (uint8_t)(i_normal >> 24);
	inZ[34] = (uint8_t)(i_normal >> 16);
	inZ[35] = (uint8_t)(i_normal >> 8);
	inZ[36] = (uint8_t)(i_normal);

	hmac_sha512_const((MN_THREAD_CONST_PTR(uint32_t))parent->chain_code,
		(MN_THREAD_CONST_PTR(uint32_t))inZ,
		(MN_THREAD_PTR(uint32_t))Z64);

	uint8_t inI2[1 + 32 + 4];
	uint8_t I2[64];
	inI2[0] = 0x03;
	memcpy(inI2 + 1, A_par, 32);
	memcpy(inI2 + 33, inZ + 33, 4);

	hmac_sha512_const((MN_THREAD_CONST_PTR(uint32_t))parent->chain_code,
		(MN_THREAD_CONST_PTR(uint32_t))inI2,
		(MN_THREAD_PTR(uint32_t))I2);

	add_modL_from_bytes(child->key, parent->key, Z64 /* IL */);

	memcpy(child->chain_code, I2 + 32, 32);
}

REC_CONSTANT uint8_t TAG_TAPTWEAK[32] = {
  0xe8,0x0f,0xe1,0x63,0x9c,0x9c,0xa0,0x50,0xe3,0xaf,0x1b,0x39,0xc1,0x43,0xc6,0x3e,
  0x42,0x9c,0xbc,0xeb,0x15,0xd9,0x40,0xfb,0xb5,0xc5,0xa1,0xf4,0xaf,0x57,0xc5,0xe9
};

// Device helper: be32.
REC_DEVICE REC_FORCEINLINE uint32_t be32(MN_THREAD_CONST_PTR(uint8_t) p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
		((uint32_t)p[2] << 8) | ((uint32_t)p[3]);
}

#if defined(__METAL_VERSION__)
REC_DEVICE REC_FORCEINLINE uint32_t be32(const constant uint8_t* p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
		((uint32_t)p[2] << 8) | ((uint32_t)p[3]);
}
#endif

// Device helper: sha256_taptweak_px.
REC_DEVICE __inline__ void sha256_taptweak_px(const uint8_t Px[32], uint8_t out[32]) {
	uint32_t H[8];
	SHA256Initialize(H);

	uint32_t w0[16];
#pragma unroll
	for (int i = 0; i < 8; i++) {
		w0[i] = be32(&TAG_TAPTWEAK[4 * i]);
		w0[i + 8] = be32(&TAG_TAPTWEAK[4 * i]);
	}
	SHA256Transform(H, w0);

	uint32_t w1[16];
#pragma unroll
	for (int i = 0; i < 8; i++) {
		w1[i] = be32(&Px[4 * i]);
	}
	w1[8] = 0x80000000U;
#pragma unroll
	for (int i = 9; i < 15; i++) w1[i] = 0;
	w1[15] = 0x00000300U;

	SHA256Transform(H, w1);

#pragma unroll
	for (int i = 0; i < 8; i++) {
		out[4 * i + 0] = (uint8_t)(H[i] >> 24);
		out[4 * i + 1] = (uint8_t)(H[i] >> 16);
		out[4 * i + 2] = (uint8_t)(H[i] >> 8);
		out[4 * i + 3] = (uint8_t)(H[i]);
	}
}

REC_DEVICE void TweakTaproot(
	SECP_THREAD uint8_t* __restrict__ out,
	const SECP_THREAD uint8_t* __restrict__ pub_uncomp,
	const SECP_CONSTANT secp256k1_ge_storage* __restrict__ precPtr,
	const size_t precPitch
) {
	secp256k1_gej gej;
	secp256k1_fe fe_in;
	secp256k1_fe fe_out;
	int produced = 0;



	MN_THREAD_CONST_PTR(uint8_t) p = &pub_uncomp[0];
	if (p[0] != 0x04) {
		gej.infinity = 1;
		return;
	}

	secp256k1_fe x, y;
	(void)secp256k1_fe_set_b32(&x, p + 1);
	(void)secp256k1_fe_set_b32(&y, p + 33);
	secp256k1_ge P;
	secp256k1_ge_set_xy(&P, &x, &y);

	secp256k1_fe_normalize_var(&P.y);
	if (secp256k1_fe_is_odd(&P.y)) {
		secp256k1_ge Pneg = P;
		secp256k1_fe_negate(&Pneg.y, &Pneg.y, 1);
		P = Pneg;
	}

	uint8_t Px[32], h[32];
	secp256k1_fe_normalize_var(&P.x);
	secp256k1_fe_get_b32(Px, &P.x);

	sha256_taptweak_px(Px, h);

	secp256k1_scalar t;
	secp256k1_scalar_set_b32(&t, h, NULL);

	secp256k1_gej tG;
#ifdef ECMULT_BIG_TABLE
	if (precPtr == nullptr || precPitch == 0u) {
		secp256k1_ecmult_gen(&tG, &t);
	} else {
		int windowLimit = WINDOWS_SIZE_CONST[0];
		unsigned int wlimit = ECMULT_WINDOW_SIZE_CONST[0];
		secp256k1_ecmult_big(&tG, &t, precPtr, precPitch, windowLimit, wlimit);
	}
#else
	secp256k1_ecmult_gen(&tG, &t);
#endif

	secp256k1_gej_add_ge_var(&gej, &tG, &P, NULL);

	if (!gej.infinity) {
		fe_in = gej.z;
		produced++;
	}
	

	if (produced > 0) {
		secp256k1_fe_inv_all_var(produced, &fe_out, &fe_in);
	}

	MN_THREAD_PTR(uint8_t) xo = &out[0];

		if (gej.infinity) {
#pragma unroll
			for (int k = 0; k < 32; k++) xo[k] = 0;
			return;
		}

		secp256k1_ge A;
		secp256k1_ge_set_gej_zinv(&A, &gej, &fe_out);

		secp256k1_fe_normalize_var(&A.y);
		if (secp256k1_fe_is_odd(&A.y)) {
			secp256k1_ge_neg(&A, &A);
		}

		secp256k1_fe_normalize_var(&A.x);
		secp256k1_fe_get_b32(xo, &A.x);
	
}

#undef MN_THREAD_PTR
#undef MN_THREAD_CONST_PTR
#undef MN_THREAD_REF
#if defined(__METAL_VERSION__)
#undef memcpy
#endif
