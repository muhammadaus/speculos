#ifndef METADATA_REGISTRY_H
#define METADATA_REGISTRY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define METADATA_HASH_SIZE 32
#define METADATA_MERKLE_PROOF_MAX_BYTES (32 * 32)

/**
 * Store the trusted Merkle root from the host/app.
 * Returns 0 on success.
 */
uint32_t sys_metadata_registry_set_merkle_root(const uint8_t *root);

/**
 * Hash raw metadata bytes on-device.
 * The wallet never trusts a pre-computed hash from the host.
 * Returns 0 on success.
 */
uint32_t sys_metadata_registry_hash_metadata(const uint8_t *metadata,
                                             size_t metadata_len,
                                             uint8_t *out_hash);

/**
 * Verify metadata against the stored Merkle root.
 *
 * 1. Hashes the raw metadata → metadataHash
 * 2. Derives approval leaf (revoked=false), folds the approval proof to the
 *    stored Merkle root → must match
 * 3. Derives revocation leaf (revoked=true), folds the revocation proof to the
 *    same stored Merkle root → must NOT match
 *
 * Returns true only if both conditions hold.
 */
bool sys_metadata_registry_verify(uint32_t chain_id,
                                  const uint8_t *extcodehash,
                                  const uint8_t *metadata,
                                  size_t metadata_len,
                                  const uint8_t *approval_proof,
                                  size_t approval_proof_len,
                                  const uint8_t *revocation_proof,
                                  size_t revocation_proof_len);

#endif /* METADATA_REGISTRY_H */
