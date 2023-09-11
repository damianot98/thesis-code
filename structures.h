//
// Created by damiano on 12/07/23.
//

#ifndef SEALING_STRUCTURES_H
#define SEALING_STRUCTURES_H

#include "tss2/tss2_tcti_mssim.h"
#include "tss2/tss2_esys.h"
#include <iostream>
#include <string>
#include <vector>

struct Key {
    ESYS_TR keyHandle;
    TPM2B_PUBLIC *outPublic;
    TPM2B_PRIVATE *outPrivate;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;
    std::vector<uint8_t> rsa_public_n;
};

struct IntegrityRequest
{
    TPM2B_DATA nonce;
    TPML_PCR_SELECTION pcrSelection;
};

struct IntegrityReport
{
    TPM2B_ATTEST attestStructure_VM;
    TPMT_SIGNATURE signatureStructure_VM;
    TPML_DIGEST pcrValues_VM;

    TPM2B_ATTEST attestStructure_VMM;
    TPMT_SIGNATURE signatureStructure_VMM;
    TPML_DIGEST pcrValues_VMM;
};

struct TpmProperties{
    int spec_version;
    std::string manufacturer_id;
};


struct CreatePrimaryResult {
    int rc;
    // Following fields are only valid if rc == TPM2_RC_SUCCESS.
    // Loaded object handle.
    uint32_t handle;
    // RSA public key material (n). Valid only if type == TPM2_ALG_RSA.
    std::vector<uint8_t> rsa_public_n;
    // ECC public key material (affine coordinates). Valid only if type ==
    // TPM2_ALG_ECC.
    std::vector<uint8_t> ecc_public_x;
    std::vector<uint8_t> ecc_public_y;
    int ecc_curve_id;
    // SYM key information
    std::vector<uint8_t> sym_cipher_buffer;
    // Copy of TPM2B_NAME. This is the hash of the canonical form of
    // tpm2b_out_public.
    std::vector<uint8_t> name;
    // Parent information from TPM2B_CREATION_DATA.
    std::vector<uint8_t> parent_name;
    std::vector<uint8_t> parent_qualified_name;
};

struct CreateResult {
    int rc;
    // Copy of TPM2B_PRIVATE buffer. Can later be used with Load.
    std::vector<uint8_t> tpm2b_private;
    // Copy of TPM2B_PUBLIC buffer. Can later be used with Load.
    std::vector<uint8_t> tpm2b_public;
    // RSA public key material (n). Valid only if type == TPM2_ALG_RSA.
    std::vector<uint8_t> rsa_public_n;
    // ECC public key material (affine coordinates). Valid only if type ==
    // TPM2_ALG_ECC.
    std::vector<uint8_t> ecc_public_x;
    std::vector<uint8_t> ecc_public_y;
    int ecc_curve_id;
    // Parent information from TPM2B_CREATION_DATA.
    std::vector<uint8_t> parent_name;
    std::vector<uint8_t> parent_qualified_name;
};


struct StartAuthSessionResult {
    int rc;
    // Following fields are only valid if rc == TPM2_RC_SUCCESS.
    ESYS_TR handle;
    std::vector<uint8_t> nonce_tpm;
};

struct LoadResult {
    int rc;
    // Following fields are only valid if rc == TPM2_RC_SUCCESS.
    // Loaded object handle.
    uint32_t handle;
    // Copy of TPM2B_NAME. This is the hash of the canonical form of
    // tpm2b_out_public.
    std::vector<uint8_t> name;
};

struct SignResult {
    int rc;
    // Following fields are only valid if rc == TPM2_RC_SUCCESS.
    int sign_algo;
    int hash_algo;
    // RSA signature. Valid only if sign_algo == TPM2_ALG_RSASSA.
    std::vector<uint8_t> rsa_ssa_sig;
    // ECDSA signature. Valid only if sign_algo == TPM2_ALG_ECDSA.
    std::vector<uint8_t> ecdsa_r;
    std::vector<uint8_t> ecdsa_s;
};

struct ReadResult{
    TPM2B_NAME keyName;
    TPM2B_PUBLIC keyPublic;
    TPM2B_NAME keyQualifiedName;
};

struct QuoteResult {
    int rc;
    // Following fields are only valid if rc == TPM2_RC_SUCCESS.
    int sign_algo;
    int hash_algo;
    // RSA signature. Valid only if sign_algo == TPM2_ALG_RSASSA.
    std::vector<uint8_t> rsa_ssa_sig;
    // Wire representation of TPMS_ATTEST structure.
    // The signature is over this buffer.
    std::vector<uint8_t> tpm2b_attest;
};


#endif //SEALING_STRUCTURES_H
