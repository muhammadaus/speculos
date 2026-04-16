#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "cx_hash.h"
#include "metadata_registry.h"

/*
 * Precomputed keccak256 of:
 *   "RegistryLeaf(uint256 chainId,bytes32 extcodehash,bytes32 metadataHash,bool
 *    revoked)"
 *
 * Matches the Solidity LEAF_TYPEHASH constant in KaiSignRegistry.sol.
 */
// clang-format off
static const uint8_t LEAF_TYPEHASH[32] = {
    0xc3, 0x9a, 0x00, 0x6f, 0x18, 0x3f, 0xd9, 0x5b,
    0xb8, 0xbe, 0x0e, 0xaa, 0xd3, 0xdf, 0x2f, 0x35,
    0x27, 0xd8, 0x79, 0x64, 0x0e, 0x93, 0xd3, 0x4b,
    0x70, 0x02, 0x31, 0x6a, 0x2f, 0x3d, 0x3e, 0x08
};
// clang-format on

/* Trusted state stored on the device */
static uint8_t merkle_root[METADATA_HASH_SIZE];

/**
 * keccak256 of raw bytes — the device hashes, never trusts the host.
 */
static void keccak256(const uint8_t *data, size_t len, uint8_t *out)
{
  cx_sha3_t ctx;
  cx_keccak_init(&ctx, 256);
  spec_cx_sha3_update(&ctx, data, len);
  spec_cx_sha3_final(&ctx, out);
}

static void hash_pair_sorted(const uint8_t *left, const uint8_t *right,
                             uint8_t *out)
{
  uint8_t pair[2 * METADATA_HASH_SIZE];

  if (memcmp(left, right, METADATA_HASH_SIZE) <= 0) {
    memcpy(pair, left, METADATA_HASH_SIZE);
    memcpy(pair + METADATA_HASH_SIZE, right, METADATA_HASH_SIZE);
  } else {
    memcpy(pair, right, METADATA_HASH_SIZE);
    memcpy(pair + METADATA_HASH_SIZE, left, METADATA_HASH_SIZE);
  }

  keccak256(pair, sizeof(pair), out);
}

/**
 * Derive a leaf hash matching Solidity's:
 *   keccak256(abi.encode(LEAF_TYPEHASH, chainId, extcodehash, metadataHash,
 *   revoked))
 */
static void compute_leaf_hash(uint32_t chain_id, const uint8_t *extcodehash,
                              const uint8_t *metadata_hash, bool revoked,
                              uint8_t *out_leaf)
{
  uint8_t abi_encoded[5 * 32];

  /* Slot 0: LEAF_TYPEHASH */
  memcpy(abi_encoded, LEAF_TYPEHASH, 32);

  /* Slot 1: chainId as uint256, big-endian left-padded */
  memset(abi_encoded + 32, 0, 32);
  abi_encoded[32 + 28] = (chain_id >> 24) & 0xFF;
  abi_encoded[32 + 29] = (chain_id >> 16) & 0xFF;
  abi_encoded[32 + 30] = (chain_id >> 8) & 0xFF;
  abi_encoded[32 + 31] = chain_id & 0xFF;

  /* Slot 2: extcodehash (already 32 bytes) */
  memcpy(abi_encoded + 64, extcodehash, 32);

  /* Slot 3: metadataHash (already 32 bytes) */
  memcpy(abi_encoded + 96, metadata_hash, 32);

  /* Slot 4: revoked — ABI-encoded bool (0 or 1 in last byte) */
  memset(abi_encoded + 128, 0, 32);
  abi_encoded[128 + 31] = revoked ? 1 : 0;

  keccak256(abi_encoded, sizeof(abi_encoded), out_leaf);
}

static bool verify_merkle_proof(const uint8_t *leaf, const uint8_t *proof,
                                size_t proof_len, const uint8_t *expected_root)
{
  uint8_t current[METADATA_HASH_SIZE];
  uint8_t next[METADATA_HASH_SIZE];

  if ((proof_len % METADATA_HASH_SIZE) != 0 ||
      proof_len > METADATA_MERKLE_PROOF_MAX_BYTES) {
    return false;
  }

  memcpy(current, leaf, sizeof(current));

  for (size_t offset = 0; offset < proof_len; offset += METADATA_HASH_SIZE) {
    hash_pair_sorted(current, proof + offset, next);
    memcpy(current, next, sizeof(current));
  }

  return memcmp(current, expected_root, METADATA_HASH_SIZE) == 0;
}

uint32_t sys_metadata_registry_set_merkle_root(const uint8_t *root)
{
  memcpy(merkle_root, root, METADATA_HASH_SIZE);
  return 0;
}

uint32_t sys_metadata_registry_hash_metadata(const uint8_t *metadata,
                                             size_t metadata_len,
                                             uint8_t *out_hash)
{
  keccak256(metadata, metadata_len, out_hash);
  return 0;
}

bool sys_metadata_registry_verify(uint32_t chain_id,
                                  const uint8_t *extcodehash,
                                  const uint8_t *metadata, size_t metadata_len,
                                  const uint8_t *approval_proof,
                                  size_t approval_proof_len,
                                  const uint8_t *revocation_proof,
                                  size_t revocation_proof_len)
{
  uint8_t metadata_hash[METADATA_HASH_SIZE];
  uint8_t approval_leaf[METADATA_HASH_SIZE];
  uint8_t revocation_leaf[METADATA_HASH_SIZE];
  bool approval_matches;
  bool revocation_matches;

  /* Step 1: Device hashes the raw metadata itself */
  keccak256(metadata, metadata_len, metadata_hash);

  /* Step 2: Derive approval leaf (revoked=false) */
  compute_leaf_hash(chain_id, extcodehash, metadata_hash, false, approval_leaf);

  /* Step 3: Derive revocation leaf (revoked=true) */
  compute_leaf_hash(chain_id, extcodehash, metadata_hash, true, revocation_leaf);

  /* Step 4: Approval proof must resolve to the stored root */
  approval_matches = verify_merkle_proof(approval_leaf, approval_proof,
                                         approval_proof_len, merkle_root);

  /*
   * Step 5: Revocation proof must NOT resolve to the same stored root.
   * An inclusion proof here means the metadata was explicitly revoked.
   */
  revocation_matches = verify_merkle_proof(revocation_leaf, revocation_proof,
                                           revocation_proof_len, merkle_root);

  return approval_matches && !revocation_matches;
}
