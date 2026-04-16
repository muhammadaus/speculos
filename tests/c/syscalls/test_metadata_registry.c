#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "bolos/cx.h"
#include "bolos/metadata_registry.h"

/**
 * Helper: keccak256 hash of raw bytes.
 * Duplicates the device-side logic so tests can pre-compute expected values.
 */
static void test_keccak256(const uint8_t *data, size_t len, uint8_t *out)
{
  cx_sha3_t ctx;
  cx_keccak_init(&ctx, 256);
  spec_cx_sha3_update(&ctx, data, len);
  spec_cx_sha3_final(&ctx, out);
}

/* Precomputed LEAF_TYPEHASH — same constant as in metadata_registry.c */
// clang-format off
static const uint8_t LEAF_TYPEHASH[32] = {
    0xc3, 0x9a, 0x00, 0x6f, 0x18, 0x3f, 0xd9, 0x5b,
    0xb8, 0xbe, 0x0e, 0xaa, 0xd3, 0xdf, 0x2f, 0x35,
    0x27, 0xd8, 0x79, 0x64, 0x0e, 0x93, 0xd3, 0x4b,
    0x70, 0x02, 0x31, 0x6a, 0x2f, 0x3d, 0x3e, 0x08
};
// clang-format on

/* Helper: compute a leaf hash the same way the device does. */
static void compute_expected_leaf(uint32_t chain_id,
                                  const uint8_t *extcodehash,
                                  const uint8_t *metadata_hash, bool revoked,
                                  uint8_t *out_leaf)
{
  uint8_t abi_encoded[5 * 32];

  memcpy(abi_encoded, LEAF_TYPEHASH, 32);

  memset(abi_encoded + 32, 0, 32);
  abi_encoded[32 + 28] = (chain_id >> 24) & 0xFF;
  abi_encoded[32 + 29] = (chain_id >> 16) & 0xFF;
  abi_encoded[32 + 30] = (chain_id >> 8) & 0xFF;
  abi_encoded[32 + 31] = chain_id & 0xFF;

  memcpy(abi_encoded + 64, extcodehash, 32);
  memcpy(abi_encoded + 96, metadata_hash, 32);

  memset(abi_encoded + 128, 0, 32);
  abi_encoded[128 + 31] = revoked ? 1 : 0;

  test_keccak256(abi_encoded, sizeof(abi_encoded), out_leaf);
}

static void hash_pair_sorted(const uint8_t *left, const uint8_t *right,
                             uint8_t *out_hash)
{
  uint8_t pair[64];

  if (memcmp(left, right, 32) <= 0) {
    memcpy(pair, left, 32);
    memcpy(pair + 32, right, 32);
  } else {
    memcpy(pair, right, 32);
    memcpy(pair + 32, left, 32);
  }

  test_keccak256(pair, sizeof(pair), out_hash);
}

/*
 * Test 1: Approved metadata resolves through a real proof to the approval
 * root, while the revocation proof does not resolve to that same root.
 *
 * Setup:
 * - approval tree has 2 leaves: target approval leaf + decoy
 * - a bogus revocation proof is checked against the same root
 * - approval proof contains the target sibling
 * - revocation proof is empty, so the target revocation leaf cannot resolve
 *   to the same root
 */
static void test_approved_metadata_returns_true(void **state
                                                __attribute__((unused)))
{
  uint32_t chain_id = 1;
  uint8_t extcodehash[32];
  memset(extcodehash, 0x11, 32);

  /* Raw metadata the host delivers to the device */
  const uint8_t metadata[] = "erc7730-uniswap-v3-router";

  /* Pre-compute what the device will derive */
  uint8_t metadata_hash[32];
  test_keccak256(metadata, sizeof(metadata) - 1, metadata_hash);

  uint8_t approval_leaf[32];
  uint8_t approval_decoy[32];
  uint8_t approval_root[32];
  uint8_t empty_proof[1] = { 0 };

  compute_expected_leaf(chain_id, extcodehash, metadata_hash, false,
                        approval_leaf);
  memset(approval_decoy, 0x42, sizeof(approval_decoy));
  hash_pair_sorted(approval_leaf, approval_decoy, approval_root);

  sys_metadata_registry_set_merkle_root(approval_root);

  assert_true(sys_metadata_registry_verify(chain_id, extcodehash, metadata,
                                           sizeof(metadata) - 1,
                                           approval_decoy,
                                           sizeof(approval_decoy), empty_proof,
                                           0));
}

/*
 * Test 2: If the same root contains both the approved leaf (revoked=false)
 * and the revoked leaf (revoked=true), revocation overrides approval.
 *
 * Setup:
 * - build a 2-leaf approval tree whose root proves the approved leaf
 * - use that approval tree root as a sibling to the revoked leaf to build a
 *   final 2-level root
 * - the approval proof is [approval_decoy, revocation_leaf]
 * - the revocation proof is [approval_root]
 *
 * Both proofs resolve to the same root, so verification must return false.
 */
static void test_revoked_metadata_returns_false(void **state
                                                __attribute__((unused)))
{
  uint32_t chain_id = 1;
  uint8_t extcodehash[32];
  memset(extcodehash, 0x11, 32);

  const uint8_t metadata[] = "erc7730-uniswap-v3-router";

  uint8_t metadata_hash[32];
  test_keccak256(metadata, sizeof(metadata) - 1, metadata_hash);

  uint8_t approval_leaf[32];
  uint8_t approval_decoy[32];
  uint8_t approval_root[32];
  uint8_t revocation_leaf[32];
  uint8_t root[32];
  uint8_t approval_proof[64];
  uint8_t revocation_proof[32];

  compute_expected_leaf(chain_id, extcodehash, metadata_hash, false,
                        approval_leaf);
  memset(approval_decoy, 0x42, sizeof(approval_decoy));
  hash_pair_sorted(approval_leaf, approval_decoy, approval_root);

  compute_expected_leaf(chain_id, extcodehash, metadata_hash, true,
                        revocation_leaf);
  hash_pair_sorted(approval_root, revocation_leaf, root);

  memcpy(approval_proof, approval_decoy, sizeof(approval_decoy));
  memcpy(approval_proof + sizeof(approval_decoy), revocation_leaf,
         sizeof(revocation_leaf));
  memcpy(revocation_proof, approval_root, sizeof(approval_root));

  sys_metadata_registry_set_merkle_root(root);

  assert_false(sys_metadata_registry_verify(chain_id, extcodehash, metadata,
                                            sizeof(metadata) - 1,
                                            approval_proof,
                                            sizeof(approval_proof),
                                            revocation_proof,
                                            sizeof(revocation_proof)));
}

/*
 * Test 3: hash_metadata produces correct keccak256 — the device hashes raw
 * bytes, never trusts the host's pre-computed hash.
 */
static void test_hash_metadata_matches_keccak256(void **state
                                                 __attribute__((unused)))
{
  const uint8_t metadata[] = "erc7730-uniswap-v3-router";

  uint8_t expected[32];
  test_keccak256(metadata, sizeof(metadata) - 1, expected);

  uint8_t actual[32];
  sys_metadata_registry_hash_metadata(metadata, sizeof(metadata) - 1, actual);

  assert_memory_equal(actual, expected, 32);
}

/*
 * Test 4: Wrong metadata doesn't match — different raw bytes produce a
 * different metadataHash, a different approval leaf, and therefore a proof
 * for the original metadata no longer resolves to the approval root.
 */
static void test_wrong_metadata_returns_false(void **state
                                              __attribute__((unused)))
{
  uint32_t chain_id = 1;
  uint8_t extcodehash[32];
  memset(extcodehash, 0x11, 32);

  /* Roots are built from the CORRECT metadata */
  const uint8_t correct_metadata[] = "erc7730-uniswap-v3-router";
  uint8_t correct_hash[32];
  test_keccak256(correct_metadata, sizeof(correct_metadata) - 1, correct_hash);

  uint8_t approval_leaf[32];
  uint8_t approval_decoy[32];
  uint8_t approval_root[32];
  uint8_t empty_proof[1] = { 0 };

  compute_expected_leaf(chain_id, extcodehash, correct_hash, false,
                        approval_leaf);
  memset(approval_decoy, 0x42, sizeof(approval_decoy));
  hash_pair_sorted(approval_leaf, approval_decoy, approval_root);

  sys_metadata_registry_set_merkle_root(approval_root);

  /* Device receives WRONG metadata */
  const uint8_t wrong_metadata[] = "erc7730-MALICIOUS-contract";
  assert_false(sys_metadata_registry_verify(chain_id, extcodehash,
                                            wrong_metadata,
                                            sizeof(wrong_metadata) - 1,
                                            approval_decoy,
                                            sizeof(approval_decoy),
                                            empty_proof, 0));
}

/*
 * Test 5: Invalid proof length is rejected.
 */
static void test_invalid_proof_length_returns_false(void **state
                                                    __attribute__((unused)))
{
  uint32_t chain_id = 1;
  uint8_t extcodehash[32];
  memset(extcodehash, 0x11, 32);

  uint8_t root[32];
  uint8_t invalid_proof[31];
  memset(root, 0x01, sizeof(root));
  memset(invalid_proof, 0x03, sizeof(invalid_proof));
  sys_metadata_registry_set_merkle_root(root);

  const uint8_t metadata[] = "anything";
  assert_false(sys_metadata_registry_verify(chain_id, extcodehash, metadata,
                                            sizeof(metadata) - 1,
                                            invalid_proof,
                                            sizeof(invalid_proof),
                                            invalid_proof,
                                            sizeof(invalid_proof)));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_approved_metadata_returns_true),
    cmocka_unit_test(test_revoked_metadata_returns_false),
    cmocka_unit_test(test_hash_metadata_matches_keccak256),
    cmocka_unit_test(test_wrong_metadata_returns_false),
    cmocka_unit_test(test_invalid_proof_length_returns_false),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
