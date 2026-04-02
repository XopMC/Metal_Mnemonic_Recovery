#include "metal/RecoveryEvalEd25519.h"
#include "metal/RecoveryEvalSecp.h"
#include "metal/RecoveryMetalTypes.h"

#include <cstddef>
#include <cstdint>
#include <iostream>

namespace {

template <typename T, typename U>
bool require_equal(const char* name, T actual, U expected) {
    if (static_cast<std::uint64_t>(actual) == static_cast<std::uint64_t>(expected)) {
        return true;
    }
    std::cerr << name << " mismatch: actual=" << static_cast<std::uint64_t>(actual)
              << " expected=" << static_cast<std::uint64_t>(expected) << '\n';
    return false;
}

}  // namespace

int main() {
    bool ok = true;

    ok &= require_equal("sizeof(ChecksumParams)", sizeof(ChecksumParams), 32u);
    ok &= require_equal("sizeof(ChecksumStageParams)", sizeof(ChecksumStageParams), 64u);
    ok &= require_equal("sizeof(SeedBatchParams)", sizeof(SeedBatchParams), 40u);
    ok &= require_equal("sizeof(FoundRecord)", sizeof(FoundRecord), 296u);
    ok &= require_equal("alignof(FoundRecord)", alignof(FoundRecord), 8u);
    ok &= require_equal("offsetof(FoundRecord.word_ids)", offsetof(FoundRecord, word_ids), 0u);
    ok &= require_equal("offsetof(FoundRecord.word_count)", offsetof(FoundRecord, word_count), 192u);
    ok &= require_equal("offsetof(FoundRecord.derivation_index)", offsetof(FoundRecord, derivation_index), 196u);
    ok &= require_equal("offsetof(FoundRecord.derivation_type)", offsetof(FoundRecord, derivation_type), 200u);
    ok &= require_equal("offsetof(FoundRecord.coin_type)", offsetof(FoundRecord, coin_type), 204u);
    ok &= require_equal("offsetof(FoundRecord.match_len)", offsetof(FoundRecord, match_len), 208u);
    ok &= require_equal("offsetof(FoundRecord.flags)", offsetof(FoundRecord, flags), 212u);
    ok &= require_equal("offsetof(FoundRecord.private_key)", offsetof(FoundRecord, private_key), 216u);
    ok &= require_equal("offsetof(FoundRecord.match_bytes)", offsetof(FoundRecord, match_bytes), 248u);
    ok &= require_equal("offsetof(FoundRecord.round_delta)", offsetof(FoundRecord, round_delta), 280u);
    ok &= require_equal("offsetof(FoundRecord.passphrase_index)", offsetof(FoundRecord, passphrase_index), 288u);
    ok &= require_equal("offsetof(FoundRecord.reserved)", offsetof(FoundRecord, reserved), 292u);

    ok &= require_equal("sizeof(ChecksumHitRecord)", sizeof(ChecksumHitRecord), 144u);
    ok &= require_equal("alignof(ChecksumHitRecord)", alignof(ChecksumHitRecord), 8u);
    ok &= require_equal("offsetof(ChecksumHitRecord.word_ids)", offsetof(ChecksumHitRecord, word_ids), 0u);
    ok &= require_equal("offsetof(ChecksumHitRecord.word_count)", offsetof(ChecksumHitRecord, word_count), 96u);
    ok &= require_equal("offsetof(ChecksumHitRecord.derivation_index)", offsetof(ChecksumHitRecord, derivation_index), 100u);
    ok &= require_equal("offsetof(ChecksumHitRecord.derivation_type)", offsetof(ChecksumHitRecord, derivation_type), 104u);
    ok &= require_equal("offsetof(ChecksumHitRecord.coin_type)", offsetof(ChecksumHitRecord, coin_type), 108u);
    ok &= require_equal("offsetof(ChecksumHitRecord.flags)", offsetof(ChecksumHitRecord, flags), 112u);
    ok &= require_equal("offsetof(ChecksumHitRecord.passphrase_index)", offsetof(ChecksumHitRecord, passphrase_index), 116u);
    ok &= require_equal("offsetof(ChecksumHitRecord.match_len)", offsetof(ChecksumHitRecord, match_len), 120u);
    ok &= require_equal("offsetof(ChecksumHitRecord.round_delta)", offsetof(ChecksumHitRecord, round_delta), 128u);
    ok &= require_equal("offsetof(ChecksumHitRecord.candidate_index)", offsetof(ChecksumHitRecord, candidate_index), 136u);

    ok &= require_equal("sizeof(MasterSeedRecord)", sizeof(MasterSeedRecord), 208u);
    ok &= require_equal("alignof(MasterSeedRecord)", alignof(MasterSeedRecord), 8u);
    ok &= require_equal("offsetof(MasterSeedRecord.hit)", offsetof(MasterSeedRecord, hit), 0u);
    ok &= require_equal("offsetof(MasterSeedRecord.master_words)", offsetof(MasterSeedRecord, master_words), 144u);

    ok &= require_equal("sizeof(RecoverySecpTargetConfig)", sizeof(RecoverySecpTargetConfig), 52u);
    ok &= require_equal("alignof(RecoverySecpTargetConfig)", alignof(RecoverySecpTargetConfig), 4u);
    ok &= require_equal("sizeof(RecoverySecpDerivationProgram)", sizeof(RecoverySecpDerivationProgram), 284u);
    ok &= require_equal("alignof(RecoverySecpDerivationProgram)", alignof(RecoverySecpDerivationProgram), 4u);
    ok &= require_equal("offsetof(RecoverySecpDerivationProgram.path_word_count)", offsetof(RecoverySecpDerivationProgram, path_word_count), 256u);
    ok &= require_equal("offsetof(RecoverySecpDerivationProgram.derivation_index)", offsetof(RecoverySecpDerivationProgram, derivation_index), 260u);
    ok &= require_equal("offsetof(RecoverySecpDerivationProgram.derivation_type)", offsetof(RecoverySecpDerivationProgram, derivation_type), 264u);
    ok &= require_equal("offsetof(RecoverySecpDerivationProgram.coin_type)", offsetof(RecoverySecpDerivationProgram, coin_type), 268u);
    ok &= require_equal("offsetof(RecoverySecpDerivationProgram.passphrase_index)", offsetof(RecoverySecpDerivationProgram, passphrase_index), 272u);
    ok &= require_equal("sizeof(RecoverySecpEvalRecord)", sizeof(RecoverySecpEvalRecord), 448u);
    ok &= require_equal("alignof(RecoverySecpEvalRecord)", alignof(RecoverySecpEvalRecord), 8u);

    ok &= require_equal("sizeof(RecoveryEd25519ExtendedPrivateKey)", sizeof(RecoveryEd25519ExtendedPrivateKey), 64u);
    ok &= require_equal("sizeof(RecoveryEd25519DerivationProgram)", sizeof(RecoveryEd25519DerivationProgram), 284u);
    ok &= require_equal("alignof(RecoveryEd25519DerivationProgram)", alignof(RecoveryEd25519DerivationProgram), 4u);
    ok &= require_equal("offsetof(RecoveryEd25519DerivationProgram.path_word_count)", offsetof(RecoveryEd25519DerivationProgram, path_word_count), 256u);
    ok &= require_equal("offsetof(RecoveryEd25519DerivationProgram.derivation_index)", offsetof(RecoveryEd25519DerivationProgram, derivation_index), 260u);
    ok &= require_equal("offsetof(RecoveryEd25519DerivationProgram.derivation_type)", offsetof(RecoveryEd25519DerivationProgram, derivation_type), 264u);
    ok &= require_equal("offsetof(RecoveryEd25519DerivationProgram.coin_type)", offsetof(RecoveryEd25519DerivationProgram, coin_type), 268u);
    ok &= require_equal("offsetof(RecoveryEd25519DerivationProgram.passphrase_index)", offsetof(RecoveryEd25519DerivationProgram, passphrase_index), 272u);
    ok &= require_equal("sizeof(RecoveryEd25519StageKernelParams)", sizeof(RecoveryEd25519StageKernelParams), 16u);
    ok &= require_equal("alignof(RecoveryEd25519StageKernelParams)", alignof(RecoveryEd25519StageKernelParams), 4u);
    ok &= require_equal("sizeof(RecoveryEd25519EvalParams)", sizeof(RecoveryEd25519EvalParams), 80u);
    ok &= require_equal("alignof(RecoveryEd25519EvalParams)", alignof(RecoveryEd25519EvalParams), 8u);
    ok &= require_equal("sizeof(RecoveryEd25519EvalRecord)", sizeof(RecoveryEd25519EvalRecord), 336u);
    ok &= require_equal("alignof(RecoveryEd25519EvalRecord)", alignof(RecoveryEd25519EvalRecord), 8u);
    ok &= require_equal("sizeof(RecoveryEd25519StageRecord)", sizeof(RecoveryEd25519StageRecord), 408u);
    ok &= require_equal("alignof(RecoveryEd25519StageRecord)", alignof(RecoveryEd25519StageRecord), 8u);
    ok &= require_equal("offsetof(RecoveryEd25519EvalParams.round_delta)", offsetof(RecoveryEd25519EvalParams, round_delta), 32u);
    ok &= require_equal("offsetof(RecoveryEd25519EvalParams.target_bytes)", offsetof(RecoveryEd25519EvalParams, target_bytes), 48u);
    ok &= require_equal("offsetof(RecoveryEd25519StageRecord.private_key)", offsetof(RecoveryEd25519StageRecord, private_key), 296u);
    ok &= require_equal("offsetof(RecoveryEd25519StageRecord.public_key)", offsetof(RecoveryEd25519StageRecord, public_key), 360u);

    return ok ? 0 : 1;
}
