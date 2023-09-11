//
// Created by damiano on 12/07/23.
//

#include "TPM.h"
#include "tss2/tss2_common.h"
#include "tss2/tss2_tpm2_types.h"
#include "tss2/tss2-tcti-tabrmd.h"
#include "tss2/tss2_mu.h"
#include "stdio.h"
#include "stdlib.h"
#include <inttypes.h>
#include <string.h>
#include <string>
#include <errno.h>
#include <openssl/evp.h>

// Marshals TPM2B structs.
template <typename T,
        TSS2_RC (*Marshaler)(T const *, uint8_t *, size_t, size_t *)>
std::vector<uint8_t> TPM2BMarshal(T const *src) {
    std::vector<uint8_t> buffer(sizeof(*src), 0);
    TSS2_RC rc = Marshaler(src, buffer.data(), buffer.size(), nullptr);
    if (rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Error during Marshalling\n");
    }
    return buffer;
}

// Unmarshals TPM2B structs.
template <typename T,
        TSS2_RC (*Unmarshaler)(uint8_t const *, size_t, size_t *, T *)>
T TPM2BUnmarshal(const std::vector<uint8_t> &buffer) {
    T result = {};
    TSS2_RC rc = Unmarshaler(buffer.data(), buffer.size(), nullptr, &result);
    if (rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Error during Unmarshalling\n");
    }
    return result;
}

TPM2B_DIGEST HashString(const std::string &str, const EVP_MD *evpmd) {
    EVP_MD_CTX *mdctx;
    TPM2B_DIGEST digest = {};
    unsigned int len = sizeof(digest.buffer);
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, evpmd, NULL);
    EVP_DigestUpdate(mdctx, str.data(), str.size());
    EVP_DigestFinal_ex(mdctx, digest.buffer, &len);
    EVP_MD_CTX_free(mdctx);
    digest.size = len;
    return digest;
}

TPM2B_PUBLIC GetPublicRSA(int restricted, int decrypt, int sign,
                          const std::vector<uint8_t> &auth_policy,
                          const TPM2B_DIGEST *unique) {
    TPM2B_PUBLIC in_public = {};
    in_public.publicArea.type = TPM2_ALG_RSA;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    if (restricted) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
    }
    if (auth_policy.empty()) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    }
    if (decrypt) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    }
    if (sign) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    }
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;

    in_public.publicArea.authPolicy.size = auth_policy.size();
    memcpy(in_public.publicArea.authPolicy.buffer, auth_policy.data(),
           auth_policy.size());

    if (sign) {
        in_public.publicArea.parameters.rsaDetail.symmetric.algorithm =
                TPM2_ALG_NULL;
    } else {
        in_public.publicArea.parameters.rsaDetail.symmetric.algorithm =
                TPM2_ALG_AES;
    }
    in_public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    in_public.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    if (sign && !decrypt) {
        in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA;
        in_public.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg =
                TPM2_ALG_SHA256;
    } else {
        in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    }
    in_public.publicArea.parameters.rsaDetail.keyBits = 2048;
    in_public.publicArea.parameters.rsaDetail.exponent = 0;
    in_public.publicArea.unique.rsa.size = 0;
    if (unique) {
//        assert(unique->size < sizeof(in_public.publicArea.unique.rsa.buffer));
        in_public.publicArea.unique.rsa.size = unique->size;
        memcpy(in_public.publicArea.unique.rsa.buffer, unique->buffer,
               unique->size);
    }
    return in_public;
}

TPM2B_PUBLIC GetPublicRSAAttributes(int restricted, int decrypt, int sign,
                          const std::vector<uint8_t> &auth_policy,
                          const TPM2B_DIGEST *unique) {
    TPM2B_PUBLIC in_public = {};
    in_public.publicArea.type = TPM2_ALG_RSA;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    if (restricted) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
    }
    if (auth_policy.empty()) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    }
    if (decrypt) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    }
    if (sign) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    }
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;

    in_public.publicArea.authPolicy.size = auth_policy.size();
    memcpy(in_public.publicArea.authPolicy.buffer, auth_policy.data(),
           auth_policy.size());

    if (sign) {
        in_public.publicArea.parameters.rsaDetail.symmetric.algorithm =
                TPM2_ALG_NULL;
    } else {
        in_public.publicArea.parameters.rsaDetail.symmetric.algorithm =
                TPM2_ALG_AES;
    }
    in_public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    in_public.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    if (sign && !decrypt) {
        in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA;
        in_public.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg =
                TPM2_ALG_SHA256;
    } else {
        in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    }
    in_public.publicArea.parameters.rsaDetail.keyBits = 2048;
    in_public.publicArea.parameters.rsaDetail.exponent = 0;
    in_public.publicArea.unique.rsa.size = 0;
    if (unique) {
//        assert(unique->size < sizeof(in_public.publicArea.unique.rsa.buffer));
        in_public.publicArea.unique.rsa.size = unique->size;
        memcpy(in_public.publicArea.unique.rsa.buffer, unique->buffer,
               unique->size);
    }
    return in_public;
}

TPM2B_PUBLIC GetPublicRSACert(int restricted, int decrypt, int sign,
                          const std::vector<uint8_t> &auth_policy,
                          const TPM2B_DIGEST *unique) {
    TPM2B_PUBLIC in_public = {};
    in_public.publicArea.type = TPM2_ALG_RSA;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    if (restricted) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
    }
    if (auth_policy.empty()) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    }
    if (decrypt) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    }
    if (sign) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    }
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_X509SIGN;

    in_public.publicArea.authPolicy.size = auth_policy.size();
    memcpy(in_public.publicArea.authPolicy.buffer, auth_policy.data(),
           auth_policy.size());

    if (sign) {
        in_public.publicArea.parameters.rsaDetail.symmetric.algorithm =
                TPM2_ALG_NULL;
    } else {
        in_public.publicArea.parameters.rsaDetail.symmetric.algorithm =
                TPM2_ALG_AES;
    }
    in_public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
    in_public.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_NULL;
    if (sign && !decrypt) {
        in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA;
        in_public.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg =
                TPM2_ALG_SHA256;
    } else {
        in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    }
    in_public.publicArea.parameters.rsaDetail.keyBits = 2048;
    in_public.publicArea.parameters.rsaDetail.exponent = 0;
    in_public.publicArea.unique.rsa.size = 0;
    if (unique) {
//        assert(unique->size < sizeof(in_public.publicArea.unique.rsa.buffer));
        in_public.publicArea.unique.rsa.size = unique->size;
        memcpy(in_public.publicArea.unique.rsa.buffer, unique->buffer,
               unique->size);
    }
    return in_public;
}

TPM2B_PUBLIC GetPublicECC(int restricted, int decrypt, int sign,
                          const std::vector<uint8_t> &auth_policy,
                          const TPM2B_DIGEST *unique) {
    TPM2B_PUBLIC in_public = {};
    in_public.publicArea.type = TPM2_ALG_ECC;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    if (restricted) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
    }
    if (auth_policy.size() == 0) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    }
    if (decrypt) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    }
    if (sign) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    }
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;

    in_public.publicArea.authPolicy.size = auth_policy.size();
//    assert(auth_policy.size() <= sizeof(in_public.publicArea.authPolicy.buffer));
    memcpy(in_public.publicArea.authPolicy.buffer, auth_policy.data(),
           auth_policy.size());

    if (sign) {
        in_public.publicArea.parameters.eccDetail.symmetric.algorithm =
                TPM2_ALG_NULL;
    } else {
        in_public.publicArea.parameters.eccDetail.symmetric.algorithm =
                TPM2_ALG_AES;
    }
    in_public.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
    in_public.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    if (sign) {
        in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
        in_public.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
                TPM2_ALG_SHA256;
    } else {
        in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
    }
    in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    in_public.publicArea.unique.ecc.x.size = 0;
    in_public.publicArea.unique.ecc.y.size = 0;
    if (unique) {
//        assert(unique->size < sizeof(in_public.publicArea.unique.ecc.x.buffer));
        in_public.publicArea.unique.ecc.x.size = unique->size;
        memcpy(in_public.publicArea.unique.ecc.x.buffer, unique->buffer,
               unique->size);
    }
    return in_public;
}

TPM2B_PUBLIC GetPublicSYM(int restricted, int decrypt, int sign,
                          const std::vector<uint8_t> &auth_policy,
                          const TPM2B_DIGEST *unique) {
    TPM2B_PUBLIC in_public = {};
    in_public.publicArea.type = TPM2_ALG_SYMCIPHER;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    if (restricted) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
    }
    if (auth_policy.size() == 0) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    }
    if (decrypt) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    }
    if (sign) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    }
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;

    in_public.publicArea.authPolicy.size = auth_policy.size();
//    assert(auth_policy.size() <= sizeof(in_public.publicArea.authPolicy.buffer));
    memcpy(in_public.publicArea.authPolicy.buffer, auth_policy.data(),
           auth_policy.size());

    in_public.publicArea.parameters.symDetail.sym.algorithm = TPM2_ALG_AES;
    in_public.publicArea.parameters.symDetail.sym.keyBits.sym = 128;
    in_public.publicArea.parameters.symDetail.sym.mode.sym = TPM2_ALG_CFB;

    in_public.publicArea.unique.sym.size = 0;
    if (unique) {
//        assert(unique->size < sizeof(in_public.publicArea.unique.sym.buffer));
        in_public.publicArea.unique.sym.size = unique->size;
        memcpy(in_public.publicArea.unique.sym.buffer, unique->buffer,
               unique->size);
    }
    return in_public;
}

TPM2B_PUBLIC GetPublicHASH(int restricted, int decrypt, int sign,
                           const std::vector<uint8_t> &auth_policy,
                           const TPM2B_DIGEST *unique,
                           const std::string &sensitive_data) {
    // When sealing sensitive data always clear restricted, decrypt and sign.
    // Additionally, clear data-origin since the TPM cannot be the data source.
    if (sensitive_data.size()) {
        restricted = decrypt = sign = 0;
    }
    TPM2B_PUBLIC in_public = {};
    in_public.publicArea.type = TPM2_ALG_KEYEDHASH;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    if (restricted) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
    }
    if (auth_policy.size() == 0) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    }
    if (decrypt) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    }
    if (sign) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    }
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
    if (sensitive_data.size() == 0) {
        in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    }

    in_public.publicArea.authPolicy.size = auth_policy.size();
//    assert(auth_policy.size() <= sizeof(in_public.publicArea.authPolicy.buffer));
    memcpy(in_public.publicArea.authPolicy.buffer, auth_policy.data(),
           auth_policy.size());

    if (sign) {
        in_public.publicArea.parameters.keyedHashDetail.scheme.scheme =
                TPM2_ALG_XOR;
        in_public.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr
                .hashAlg = TPM2_ALG_SHA256;
        in_public.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr
                .kdf = TPM2_ALG_KDF1_SP800_108;
    } else {
        in_public.publicArea.parameters.keyedHashDetail.scheme.scheme =
                TPM2_ALG_NULL;
    }

    in_public.publicArea.unique.keyedHash.size = 0;
    if (unique) {
//        assert(unique->size < sizeof(in_public.publicArea.unique.keyedHash.buffer));
        in_public.publicArea.unique.keyedHash.size = unique->size;
        memcpy(in_public.publicArea.unique.keyedHash.buffer, unique->buffer,
               unique->size);
    }
    return in_public;
}

TPM2B_SENSITIVE_CREATE BuildInSensitive(const std::string &user_auth,
                                        const std::string &sensitive_data) {
    TPM2B_SENSITIVE_CREATE in_sensitive = {};
    in_sensitive.sensitive.userAuth.size = user_auth.size();
    memcpy(in_sensitive.sensitive.userAuth.buffer, user_auth.c_str(),
           user_auth.size());

    in_sensitive.sensitive.data.size = sensitive_data.size();
    memcpy(in_sensitive.sensitive.data.buffer, sensitive_data.c_str(),
           sensitive_data.size());
    return in_sensitive;
}


TPM::TPM(int number) {
    Init_Tcti_Tabrmd_Context();
    Init_Esys_Context();

    fprintf(stdout, "TPM instantiation successfull\n");

    identifier = number;
}

TPM::~TPM() {
    Finalize_Esys_Context();
    Finalize_Tcti_Tabrmd_Context();

    fprintf(stdout, "TPM finalization successfull \n");
}

int TPM::ErrorHandling(TSS2_RC rc) {
    switch (rc)
    {
        case TSS2_RC_SUCCESS :
            return 1;
        case TSS2_ESYS_RC_BAD_REFERENCE:
            fprintf(stderr,"Bad Reference: the esysContext or required input pointers or required output handle references are NULL(0x%" PRIx32 " )\n",rc);
            return 0;
        case TSS2_ESYS_RC_MEMORY:
            fprintf(stderr,"he ESAPI cannot allocate enough memory for internal operations or return parameters(0x%" PRIx32 " )\n",rc);
            return 0;
        case TSS2_ESYS_RC_BAD_SEQUENCE:
            fprintf(stderr,"the context has an asynchronous operation already pending(0x%" PRIx32 " )\n",rc);
            return 0;
        case TSS2_ESYS_RC_INSUFFICIENT_RESPONSE:
            fprintf(stderr,"the TPM's response does not at least contain the tag, response length, and response code(0x%" PRIx32 " )\n",rc);
            return 0;
        case TSS2_ESYS_RC_MALFORMED_RESPONSE:
            fprintf(stderr,"the TPM's response is corrupted(0x%" PRIx32 " )\n",rc);
            return 0;
        case TSS2_ESYS_RC_RSP_AUTH_FAILED:
            fprintf(stderr,"the response HMAC from the TPM did not verify(0x%" PRIx32 " )\n",rc);
            return 0;
        case TSS2_ESYS_RC_MULTIPLE_DECRYPT_SESSIONS:
            fprintf(stderr,"more than one session has the 'decrypt' attribute bit set(0x%" PRIx32 " )\n",rc);
            return 0;
        case TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS:
            fprintf(stderr,"more than one session has the 'decrypt' attribute bit set(0x%" PRIx32 " )\n",rc);
            return 0;
        case TSS2_ESYS_RC_BAD_TR:
            fprintf(stderr,"ny of the ESYS_TR objects are unknown to the ESYS_CONTEXT or are of the wrong type or if required ESYS_TR objects are ESYS_TR_NONE(0x%" PRIx32 " )\n",rc);
            return 0;
        case TSS2_ESYS_RC_NO_ENCRYPT_PARAM:
            fprintf(stderr,"one of the sessions has the 'encrypt' attribute set and the command does not support encryption of the first response parameter(0x%" PRIx32 " )\n",rc);
            return 0;
        case TPM2_RC_NV_UNINITIALIZED:
            fprintf(stdout,"Read of NV location before it is written: 0x%" PRIx32 "\n", rc);
            return 0;
        case TSS2_RESMGR_RC_LAYER | TSS2_RESMGR_TPM_RC_LAYER:
            fprintf(stderr,"Command TPM2_GetCommandAuditDigest not supported by TPM : 0x%" PRIx32 " \n",rc);
            return 0;
        default:
            fprintf(stderr,"Error number : 0x%" PRIx32 " \n",rc);
            return 0;
    }
}

void TPM::Free(void *resourceObject){
    Esys_Free(resourceObject);
}


void TPM::Init_Tcti_Tabrmd_Context() {
    TSS2_RC rc;
    size_t context_size;

    //Define allocation for the mssim TCTI
    /*
        TSS2_RC Tss2_Tcti_Tabrmd_Init (TSS2_TCTI_CONTEXT *tcti_context, size_t *size, const char *conf)
        minimum size of the context => pass NULL to conf
        *tcti_context => desired connection properties for the TCTI
    */
    rc = Tss2_Tcti_Tabrmd_Init(nullptr, &context_size, NULL);
    if(!ErrorHandling(rc))
    {
        fprintf(stdout,"Failed to get allocation size for mssim TCTI \n");
        exit(EXIT_FAILURE);
    }

    tcti_context = (TSS2_TCTI_CONTEXT *) calloc(1,context_size);
    if(!ErrorHandling(rc))
    {
        fprintf(stdout, "Allocation for TCTI context failed: %s0 \n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    rc = Tss2_Tcti_Tabrmd_Init(tcti_context,&context_size, NULL);
    if(!ErrorHandling(rc))
    {
        fprintf(stdout, "Failed to initialize tabrmd TCTI context: 0x%" PRIx32 "0\n", rc);
        free(tcti_context);
        exit(EXIT_FAILURE);
    }

    fprintf(stdout,"Initialization of the TCTI context successfull \n");
}



void TPM::Finalize_Tcti_Tabrmd_Context() {
    Esys_Finalize(&esys_context);
    free(tcti_context);

    fprintf(stdout,"Finalization of the Esys context \n");
}

void TPM::Init_Esys_Context() {
    TSS2_RC rc;
    TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;

    //Initialization of the ESYS context
    /*
        TSS2_RC Esys_Initialize( ESYS_CONTEXT **esysContext, TSS2_TCTI_CONTEXT *tcti, TSS2_ABI_VERSION *abiVersion);
        esysContext => reference to a pointer to the opaque ESYS_CONTEXT blob. It must be not NULL
        tcti => pointer to the TCTI context
        abiVersion => pointer to the ABI version that the application requests
    */
    rc = Esys_Initialize(&esys_context,tcti_context,&abi_version);
    if (rc != TSS2_RC_SUCCESS)
    {
        fprintf(stderr,"Failed to initialize the ESYS context: 0x%" PRIx32 "0 \n", rc);
        free(tcti_context);
        exit(EXIT_FAILURE);
    }

    fprintf(stdout,"Initialization of the ESYS context successfull \n");
}


void TPM::Finalize_Esys_Context() {
    Tss2_Tcti_Finalize(tcti_context);

    fprintf(stdout,"Finalization of the TCTI context \n");
}

TSS2_RC TPM::FlushContext(uint32_t handle) {
    return Esys_FlushContext(esys_context, handle);
}

CreatePrimaryResult
TPM::CreatePrimaryFromTemplate(ESYS_TR hierarchy,
                               const TPM2B_SENSITIVE_CREATE &in_sensitive,
                               const TPM2B_PUBLIC &in_public,
                               int session_handle) {
    TPM2B_PUBLIC *out_public;

    TPM2B_DATA outside_info;
    outside_info.size = 0;

    TPML_PCR_SELECTION creation_pcr;
    creation_pcr.count = 0;

    TPM2B_CREATION_DATA *creation_data;

    TPM2B_DIGEST *creation_hash;
    TPMT_TK_CREATION *creation_ticket;

    CreatePrimaryResult result = {};


    result.rc = Esys_CreatePrimary(esys_context, hierarchy, session_handle, ESYS_TR_NONE, ESYS_TR_NONE, &in_sensitive, &in_public, &outside_info,
                                   &creation_pcr, &result.handle, &out_public, &creation_data, &creation_hash, &creation_ticket);

    if (result.rc == TPM2_RC_SUCCESS) {
        if (in_public.publicArea.type == TPM2_ALG_RSA) {
            result.rsa_public_n =
                    std::vector<uint8_t>(out_public->publicArea.unique.rsa.buffer,
                                         out_public->publicArea.unique.rsa.buffer +
                                         out_public->publicArea.unique.rsa.size);
        } else if (in_public.publicArea.type == TPM2_ALG_ECC) {
            result.ecc_public_x =
                    std::vector<uint8_t>(out_public->publicArea.unique.ecc.x.buffer,
                                         out_public->publicArea.unique.ecc.x.buffer +
                                         out_public->publicArea.unique.ecc.x.size);
            result.ecc_public_y =
                    std::vector<uint8_t>(out_public->publicArea.unique.ecc.y.buffer,
                                         out_public->publicArea.unique.ecc.y.buffer +
                                         out_public->publicArea.unique.ecc.y.size);
            result.ecc_curve_id = out_public->publicArea.parameters.eccDetail.curveID;
        } else if (in_public.publicArea.type == TPM2_ALG_SYMCIPHER){
            result.sym_cipher_buffer =
                    std::vector<uint8_t>(out_public->publicArea.unique.sym.buffer,
                                         out_public->publicArea.unique.sym.buffer +
                                         out_public->publicArea.unique.sym.size);
        }

        result.parent_name =
                std::vector<uint8_t>(creation_data->creationData.parentName.name,
                                     creation_data->creationData.parentName.name +
                                     creation_data->creationData.parentName.size);

        result.parent_qualified_name = std::vector<uint8_t>(
                creation_data->creationData.parentQualifiedName.name,
                creation_data->creationData.parentQualifiedName.name +
                creation_data->creationData.parentQualifiedName.size);
    }

    return result;
}

CreatePrimaryResult TPM::CreatePrimary(int hierarchy, int type, int restricted, int decrypt,
                                       int sign, const std::string &unique,
                                       const std::string &user_auth,
                                       const std::string &sensitive_data,
                                       const std::vector<uint8_t> &auth_policy,
                                       int session_handle) {
    if ((hierarchy != ESYS_TR_RH_NULL) && (hierarchy != ESYS_TR_RH_ENDORSEMENT) &&
        (hierarchy != ESYS_TR_RH_PLATFORM) && (hierarchy != ESYS_TR_RH_OWNER)){
        fprintf(stderr, "Wrong hierarchy provided");
        exit(1);
    }

    if ((type != TPM2_ALG_RSA) && (type != TPM2_ALG_ECC) &&
        (type != TPM2_ALG_SYMCIPHER) && (type != TPM2_ALG_KEYEDHASH)){
        fprintf(stderr, "Wrong algorithm provided");
        exit(1);
    }

    TPM2B_DIGEST unique_digest = HashString(unique, EVP_sha256());

    TPM2B_PUBLIC in_public = {};
    if (type == TPM2_ALG_RSA) {
        in_public =
                GetPublicRSA(restricted, decrypt, sign, auth_policy, &unique_digest);
    } else if (type == TPM2_ALG_ECC) {
        in_public =
                GetPublicECC(restricted, decrypt, sign, auth_policy, &unique_digest);
    } else if (type == TPM2_ALG_SYMCIPHER) {
        in_public =
                GetPublicSYM(restricted, decrypt, sign, auth_policy, &unique_digest);
    } else /* type == TPM2_ALG_KEYEDHASH*/ {
        in_public = GetPublicHASH(restricted, decrypt, sign, auth_policy,
                                  &unique_digest, sensitive_data);
    }
    TPM2B_SENSITIVE_CREATE in_sensitive =
            BuildInSensitive(user_auth, sensitive_data);

    return CreatePrimaryFromTemplate(hierarchy, in_sensitive, in_public, session_handle);
}

CreatePrimaryResult TPM::CreatePrimaryCert(int hierarchy, int type, int restricted, int decrypt,
                                       int sign, const std::string &unique,
                                       const std::string &user_auth,
                                       const std::string &sensitive_data,
                                       const std::vector<uint8_t> &auth_policy,
                                       int session_handle) {
    if ((hierarchy != ESYS_TR_RH_NULL) && (hierarchy != ESYS_TR_RH_ENDORSEMENT) &&
        (hierarchy != ESYS_TR_RH_PLATFORM) && (hierarchy != ESYS_TR_RH_OWNER)){
        fprintf(stderr, "Wrong hierarchy provided");
        exit(1);
    }

    if ((type != TPM2_ALG_RSA) && (type != TPM2_ALG_ECC) &&
        (type != TPM2_ALG_SYMCIPHER) && (type != TPM2_ALG_KEYEDHASH)){
        fprintf(stderr, "Wrong algorithm provided");
        exit(1);
    }

    TPM2B_DIGEST unique_digest = HashString(unique, EVP_sha256());

    TPM2B_PUBLIC in_public = {};
    if (type == TPM2_ALG_RSA) {
        in_public =
                GetPublicRSACert(restricted, decrypt, sign, auth_policy, &unique_digest);
    } else if (type == TPM2_ALG_ECC) {
        in_public =
                GetPublicECC(restricted, decrypt, sign, auth_policy, &unique_digest);
    } else if (type == TPM2_ALG_SYMCIPHER) {
        in_public =
                GetPublicSYM(restricted, decrypt, sign, auth_policy, &unique_digest);
    } else /* type == TPM2_ALG_KEYEDHASH*/ {
        in_public = GetPublicHASH(restricted, decrypt, sign, auth_policy,
                                  &unique_digest, sensitive_data);
    }
    TPM2B_SENSITIVE_CREATE in_sensitive =
            BuildInSensitive(user_auth, sensitive_data);

    return CreatePrimaryFromTemplate(hierarchy, in_sensitive, in_public, session_handle);
}

StartAuthSessionResult TPM::StartAuthSession(int session_type, bool is_symmetric, uint32_t handle) {

    ESYS_TR session = ESYS_TR_NONE;

    TPM2B_NONCE nonce_caller = {
            .size = TPM2_SHA256_DIGEST_SIZE,
            .buffer = {0},
    };

    TPMT_SYM_DEF symmetric = {
            .algorithm = TPM2_ALG_NULL
    };

    if (is_symmetric){
        symmetric.algorithm = TPM2_ALG_AES;
        symmetric.keyBits.aes = 128;
        symmetric.mode.aes = TPM2_ALG_CFB;
    }

    TPMA_SESSION sessionAttributes(TPMA_SESSION_DECRYPT|TPMA_SESSION_ENCRYPT|TPMA_SESSION_CONTINUESESSION);
    TPM2_SE sessionType;

    switch(session_type){
        case 1:
            sessionType = TPM2_SE_TRIAL;
            break;
        case 2:
            sessionType = TPM2_SE_POLICY;
            break;
        default:
            sessionType = TPM2_SE_HMAC;
            break;
    }

    TPMI_ALG_HASH authHash = TPM2_ALG_SHA256;

    StartAuthSessionResult result = {};

    result.rc = Esys_StartAuthSession(esys_context, handle, ESYS_TR_NONE,
                                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nonce_caller,
                                      sessionType, &symmetric, authHash, &session);


    if (result.rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Error with StartAuthSession\n");
        exit(1);
    }else{
        result.handle = session;
        result.nonce_tpm = std::vector<uint8_t>(nonce_caller.buffer, nonce_caller.buffer+nonce_caller.size);
    }

    result.rc = Esys_TRSess_SetAttributes(esys_context, session, sessionAttributes, 0xff);

    if (result.rc != TPM2_RC_SUCCESS) {
        fprintf(stderr, "Error with TRSess_SetAttributes\n");
        exit(1);
    }

    return result;
}

TPM2B_DIGEST* TPM::PolicyPCR(ESYS_TR pcr_handle, ESYS_TR session_handle, const std::vector<uint8_t> &digest){

    TPML_PCR_SELECTION pcrSelection;
    pcrSelection.count = 1;
    pcrSelection.pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcrSelection.pcrSelections[0].sizeofSelect = 3;
    pcrSelection.pcrSelections[0].pcrSelect[2] = 0x00;
    pcrSelection.pcrSelections[0].pcrSelect[1] = 0x00;
    pcrSelection.pcrSelections[0].pcrSelect[0] = 0x00;
    pcrSelection.pcrSelections[0].pcrSelect[2] |= (1 << 7);

    TPM2B_DIGEST pcr_digest_zero;
    pcr_digest_zero.size = digest.size();
    std::copy(digest.begin(), digest.end(), pcr_digest_zero.buffer);

    TPM2B_DIGEST *policyDigest;

    TSS2_RC r = Esys_PolicyGetDigest(esys_context,
                                     session_handle,
                                     ESYS_TR_NONE,
                                     ESYS_TR_NONE, ESYS_TR_NONE, &policyDigest);

    if (r!=TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldnt get the policy digest\n");
        exit(-1);
    }

    std::cout << "PolicyDigest before function execution: " << OPENSSL_buf2hexstr(policyDigest->buffer, policyDigest->size) << "\n";

    TSS2_RC rc =  Esys_PolicyPCR(esys_context, session_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 &pcr_digest_zero, &pcrSelection);

    if (rc!=TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldnt execute the policyPCR function\n");
        exit(-1);
    }

    r = Esys_PolicyGetDigest(esys_context,
                             session_handle,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &policyDigest);

    if (r!=TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldnt get the policy digest\n");
        exit(-1);
    }

    std::cout << "PolicyDigest after PolicyPCR: " << OPENSSL_buf2hexstr(policyDigest->buffer, policyDigest->size) << "\n";

    return policyDigest;
}

CreateResult TPM::Create(uint32_t parent_handle, int type, int restricted,
                         int decrypt, int sign, const std::string &user_auth,
                         const std::string &sensitive_data,
                         const std::vector<uint8_t> &auth_policy,
                         int session_handle) {

    if ((type != TPM2_ALG_RSA) && (type != TPM2_ALG_ECC) &&
        (type != TPM2_ALG_SYMCIPHER) && (type != TPM2_ALG_KEYEDHASH)){
        fprintf(stderr, "Error wrong algorithm\n");
    }

    TPM2B_PUBLIC in_public = {};
    if (type == TPM2_ALG_RSA) {
        in_public = GetPublicRSA(restricted, decrypt, sign, auth_policy, nullptr);
    } else if (type == TPM2_ALG_ECC) {
        in_public = GetPublicECC(restricted, decrypt, sign, auth_policy, nullptr);
    } else if (type == TPM2_ALG_SYMCIPHER) {
        in_public = GetPublicSYM(restricted, decrypt, sign, auth_policy, nullptr);
    } else /* type == TPM2_ALG_KEYEDHASH*/ {
        in_public = GetPublicHASH(restricted, decrypt, sign, auth_policy, nullptr,
                                  sensitive_data);
    }

    TPM2B_PUBLIC *out_public;

    TPM2B_SENSITIVE_CREATE in_sensitive =
            BuildInSensitive(user_auth, sensitive_data);

    TPM2B_DATA outside_info;
    outside_info.size = 0;

    TPML_PCR_SELECTION creation_pcr;
    creation_pcr.count = 0;

    TPM2B_PRIVATE *out_private;

    TPM2B_CREATION_DATA *creation_data;

    TPM2B_DIGEST *creation_hash;
    TPMT_TK_CREATION *creation_ticket;

    CreateResult result = {};

    result.rc = Esys_Create(esys_context, parent_handle, session_handle,
                            ESYS_TR_NONE, ESYS_TR_NONE, &in_sensitive,
                            &in_public, &outside_info, &creation_pcr,
                            &out_private, &out_public, &creation_data,
                            &creation_hash, &creation_ticket);

    std::vector<unsigned char> bufferVector(out_private->buffer, out_private->buffer+out_private->size);
    const unsigned char * keyData = bufferVector.data();

    if (result.rc == TPM2_RC_SUCCESS) {
        if (type == TPM2_ALG_RSA) {
            result.rsa_public_n =
                    std::vector<uint8_t>(out_public->publicArea.unique.rsa.buffer,
                                         out_public->publicArea.unique.rsa.buffer +
                                         out_public->publicArea.unique.rsa.size);
        } else if (type == TPM2_ALG_ECC) {
            result.ecc_public_x =
                    std::vector<uint8_t>(out_public->publicArea.unique.ecc.x.buffer,
                                         out_public->publicArea.unique.ecc.x.buffer +
                                         out_public->publicArea.unique.ecc.x.size);
            result.ecc_public_y =
                    std::vector<uint8_t>(out_public->publicArea.unique.ecc.y.buffer,
                                         out_public->publicArea.unique.ecc.y.buffer +
                                         out_public->publicArea.unique.ecc.y.size);
            result.ecc_curve_id = out_public->publicArea.parameters.eccDetail.curveID;
        }
        result.tpm2b_private =
                TPM2BMarshal<TPM2B_PRIVATE, Tss2_MU_TPM2B_PRIVATE_Marshal>(
                        out_private);
        result.tpm2b_public =
                TPM2BMarshal<TPM2B_PUBLIC, Tss2_MU_TPM2B_PUBLIC_Marshal>(out_public);
        result.parent_name =
                std::vector<uint8_t>(creation_data->creationData.parentName.name,
                                     creation_data->creationData.parentName.name +
                                     creation_data->creationData.parentName.size);

        result.parent_qualified_name = std::vector<uint8_t>(
                creation_data->creationData.parentQualifiedName.name,
                creation_data->creationData.parentQualifiedName.name +
                creation_data->creationData.parentQualifiedName.size);
    }

    return result;
}

LoadResult TPM::Load(ESYS_TR parent_handle, const std::vector<uint8_t> &tpm2b_private, const std::vector<uint8_t> &tpm2b_public, int session_handle) {

    TPM2B_PRIVATE in_private = TPM2BUnmarshal<TPM2B_PRIVATE, Tss2_MU_TPM2B_PRIVATE_Unmarshal>(tpm2b_private);

    TPM2B_PUBLIC in_public = TPM2BUnmarshal<TPM2B_PUBLIC, Tss2_MU_TPM2B_PUBLIC_Unmarshal>(tpm2b_public);

    TPM2B_NAME *name;

    LoadResult result = {};

    result.rc = Esys_Load(esys_context, parent_handle, session_handle, ESYS_TR_NONE, ESYS_TR_NONE, &in_private, &in_public, &result.handle);

    if (result.rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Error loading the child key\n");
        exit(1);
    }else{
        fprintf(stdout, "Loading child key successful\n");
    }

    Esys_ReadPublic(esys_context, parent_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, &name, NULL);

    if (result.rc == TPM2_RC_SUCCESS) {
        result.name = std::vector<uint8_t>(name->name, name->name + name->size);
    }

    return result;
}

std::vector<uint8_t> TPM::EncryptRSAWithSession(uint32_t key_handle,
                                                const std::vector<uint8_t> &message,
                                                uint32_t session_handle) {

    TPM2B_PUBLIC_KEY_RSA inData = {};
    inData.size = message.size();
    memcpy(inData.buffer, message.data(), message.size());

    TPM2B_PUBLIC_KEY_RSA *data_out;

    TPMT_RSA_DECRYPT scheme = {
            .scheme = TPM2_ALG_RSAES,
    };

    TPM2_RC rc;

    TPM2B_DATA outsideInfo;

    rc = Esys_RSA_Encrypt(esys_context, key_handle, session_handle, ESYS_TR_NONE,
                          ESYS_TR_NONE, &inData, &scheme, &outsideInfo, &data_out);


    if (rc!=TPM2_RC_SUCCESS){
        fprintf(stderr, "Error: RSAEncrypted\n");
        exit(1);
    }

    return std::vector<uint8_t>(data_out->buffer, data_out->buffer + data_out->size);
}

std::vector<uint8_t> TPM::DecryptRSAWithSession(uint32_t key_handle,
                                                const std::vector<uint8_t> &message,
                                                uint32_t session_handle) {

    TPM2B_PUBLIC_KEY_RSA inData = {};
    inData.size = message.size();
    memcpy(inData.buffer, message.data(), message.size());

    TPM2B_PUBLIC_KEY_RSA *data_out;

    TPMT_RSA_DECRYPT scheme = {
            .scheme = TPM2_ALG_RSAES,
    };

    TPM2_RC rc;

    TPM2B_DATA outsideInfo;

    rc = Esys_RSA_Decrypt(esys_context, key_handle, session_handle, ESYS_TR_NONE,
                          ESYS_TR_NONE, &inData, &scheme, &outsideInfo, &data_out);

    if (rc!=TPM2_RC_SUCCESS) {
        fprintf(stderr, "Error: RSADecrypt\n");
        exit(1);
    }

    return std::vector<uint8_t>(data_out->buffer, data_out->buffer + data_out->size);
}

TPMS_CONTEXT* TPM::ContextSave(uint32_t key_handle){
    ESYS_TR rc;
    TPMS_CONTEXT *context = NULL;

    rc =  Esys_ContextSave(esys_context, key_handle, &context);

    if (rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn´t save the context\n");
    }

    return context;
}

SignResult TPM::Sign(uint32_t key_handle, int type, const std::string &str, uint32_t session_handle) {

    if ((type != TPM2_ALG_RSA) && (type != TPM2_ALG_ECC)){
        fprintf(stderr, "Wrong algorithm provided\n");
        exit(1);
    }

    TPM2B_DIGEST message = HashString(str, EVP_sha256());

    // Use the object's default scheme.
    TPMT_SIG_SCHEME scheme = {};

    if (type == TPM2_ALG_RSA) {
        scheme.scheme = TPM2_ALG_RSASSA;
        scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
    } else { /* type == TPM2_ALG_ECC */
        scheme.scheme = TPM2_ALG_ECDSA;
        scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
    }

    TPMT_TK_HASHCHECK validation = {};
    validation.tag = TPM2_ST_HASHCHECK;
    validation.hierarchy = TPM2_RH_NULL;
    validation.digest.size = 0;

    TPMT_SIGNATURE *signature;
    SignResult result;


    result.rc = Esys_Sign(esys_context, key_handle, session_handle,
                          ESYS_TR_NONE, ESYS_TR_NONE, &message, &scheme, &validation, &signature);

    if (result.rc == TPM2_RC_SUCCESS) {
        result.sign_algo = signature->sigAlg;
        if (type == TPM2_ALG_RSA) {
            result.hash_algo = signature->signature.rsassa.hash;
            result.rsa_ssa_sig =
                    std::vector<uint8_t>(signature->signature.rsassa.sig.buffer,
                                         signature->signature.rsassa.sig.buffer +
                                         signature->signature.rsassa.sig.size);
        } else { /* type == TPM2_ALG_ECC */
            result.hash_algo = signature->signature.ecdsa.hash;
            result.ecdsa_r =
                    std::vector<uint8_t>(signature->signature.ecdsa.signatureR.buffer,
                                         signature->signature.ecdsa.signatureR.buffer +
                                         signature->signature.ecdsa.signatureR.size);
            result.ecdsa_s =
                    std::vector<uint8_t>(signature->signature.ecdsa.signatureS.buffer,
                                         signature->signature.ecdsa.signatureS.buffer +
                                         signature->signature.ecdsa.signatureS.size);
        }
    }
    return result;
}

TPM2_RC TPM::VerifySignature(uint32_t key_handle, const std::string &str, const SignResult &in_signature, uint32_t session_handle) {

    TPM2B_DIGEST message = HashString(str, EVP_sha256());
    TPMT_SIGNATURE signature = {};

    signature.sigAlg = in_signature.sign_algo;

    if (signature.sigAlg == TPM2_ALG_RSASSA) {
        signature.signature.rsassa.hash = in_signature.hash_algo;
        memcpy(signature.signature.rsassa.sig.buffer,
               in_signature.rsa_ssa_sig.data(), in_signature.rsa_ssa_sig.size());
        signature.signature.rsassa.sig.size = in_signature.rsa_ssa_sig.size();
    } else if (signature.sigAlg == TPM2_ALG_ECDSA) {
        signature.signature.ecdsa.hash = in_signature.hash_algo;

        memcpy(signature.signature.ecdsa.signatureR.buffer,
               in_signature.ecdsa_r.data(), in_signature.ecdsa_r.size());
        signature.signature.ecdsa.signatureR.size = in_signature.ecdsa_r.size();

        memcpy(signature.signature.ecdsa.signatureS.buffer,
               in_signature.ecdsa_s.data(), in_signature.ecdsa_s.size());
        signature.signature.ecdsa.signatureS.size = in_signature.ecdsa_s.size();
    }

    TPMT_TK_VERIFIED *validation;

    return Esys_VerifySignature(esys_context, key_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &message, &signature, &validation);
}

CreateResult TPM::CreateWithAttributes(uint32_t parent_handle, int type, int restricted,
                         int decrypt, int sign, const std::string &user_auth,
                         const std::string &sensitive_data,
                         const std::vector<uint8_t> &auth_policy,
                         int session_handle) {

    if ((type != TPM2_ALG_RSA) && (type != TPM2_ALG_ECC) &&
        (type != TPM2_ALG_SYMCIPHER) && (type != TPM2_ALG_KEYEDHASH)){
        fprintf(stderr, "Error wrong algorithm\n");
    }

    TPM2B_PUBLIC in_public = {};
    if (type == TPM2_ALG_RSA) {
        in_public = GetPublicRSAAttributes(restricted, decrypt, sign, auth_policy, nullptr);
    } else if (type == TPM2_ALG_ECC) {
        in_public = GetPublicECC(restricted, decrypt, sign, auth_policy, nullptr);
    } else if (type == TPM2_ALG_SYMCIPHER) {
        in_public = GetPublicSYM(restricted, decrypt, sign, auth_policy, nullptr);
    } else /* type == TPM2_ALG_KEYEDHASH*/ {
        in_public = GetPublicHASH(restricted, decrypt, sign, auth_policy, nullptr,
                                  sensitive_data);
    }

    TPM2B_PUBLIC *out_public;

    TPM2B_SENSITIVE_CREATE in_sensitive =
            BuildInSensitive(user_auth, sensitive_data);

    TPM2B_DATA outside_info;
    outside_info.size = 0;

    TPML_PCR_SELECTION creation_pcr;
    creation_pcr.count = 0;

    TPM2B_PRIVATE *out_private;

    TPM2B_CREATION_DATA *creation_data;

    TPM2B_DIGEST *creation_hash;
    TPMT_TK_CREATION *creation_ticket;

    CreateResult result = {};

    result.rc = Esys_Create(esys_context, parent_handle, session_handle,
                            ESYS_TR_NONE, ESYS_TR_NONE, &in_sensitive,
                            &in_public, &outside_info, &creation_pcr,
                            &out_private, &out_public, &creation_data,
                            &creation_hash, &creation_ticket);

    std::vector<unsigned char> bufferVector(out_private->buffer, out_private->buffer+out_private->size);
    const unsigned char * keyData = bufferVector.data();

    if (result.rc == TPM2_RC_SUCCESS) {
        if (type == TPM2_ALG_RSA) {
            result.rsa_public_n =
                    std::vector<uint8_t>(out_public->publicArea.unique.rsa.buffer,
                                         out_public->publicArea.unique.rsa.buffer +
                                         out_public->publicArea.unique.rsa.size);
        } else if (type == TPM2_ALG_ECC) {
            result.ecc_public_x =
                    std::vector<uint8_t>(out_public->publicArea.unique.ecc.x.buffer,
                                         out_public->publicArea.unique.ecc.x.buffer +
                                         out_public->publicArea.unique.ecc.x.size);
            result.ecc_public_y =
                    std::vector<uint8_t>(out_public->publicArea.unique.ecc.y.buffer,
                                         out_public->publicArea.unique.ecc.y.buffer +
                                         out_public->publicArea.unique.ecc.y.size);
            result.ecc_curve_id = out_public->publicArea.parameters.eccDetail.curveID;
        }
        result.tpm2b_private =
                TPM2BMarshal<TPM2B_PRIVATE, Tss2_MU_TPM2B_PRIVATE_Marshal>(
                        out_private);
        result.tpm2b_public =
                TPM2BMarshal<TPM2B_PUBLIC, Tss2_MU_TPM2B_PUBLIC_Marshal>(out_public);
        result.parent_name =
                std::vector<uint8_t>(creation_data->creationData.parentName.name,
                                     creation_data->creationData.parentName.name +
                                     creation_data->creationData.parentName.size);

        result.parent_qualified_name = std::vector<uint8_t>(
                creation_data->creationData.parentQualifiedName.name,
                creation_data->creationData.parentQualifiedName.name +
                creation_data->creationData.parentQualifiedName.size);
    }

    return result;
}

TPM2B_DIGEST* TPM::PolicyCMD(ESYS_TR session_handle){
    TSS2_RC rc;
    TPM2B_DIGEST *policyDigestCMD;

    rc = Esys_PolicyCommandCode(esys_context,
                               session_handle,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               TPM2_CC_Duplicate
    );

    if (rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn't execute PolicyCommandCode function\n");
    }

    rc = Esys_PolicyGetDigest(esys_context,
                             session_handle,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &policyDigestCMD
    );

    if (rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn't get the PolicyDigestCMD\n");
    }

    return policyDigestCMD;
}

TPM2B_DIGEST* TPM::PolicyOR(ESYS_TR session_handle, TPML_DIGEST digest_list){
    TSS2_RC rc;
    TPM2B_DIGEST *policyDigestOR;

    rc = Esys_PolicyOR(esys_context,
                      session_handle,
                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &digest_list);

    if (rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn't execute the PolicyOR function\n");
    }

    rc = Esys_PolicyGetDigest(esys_context,
                              session_handle,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              &policyDigestOR
    );

    if (rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn't get the PolicyDigestCMD\n");
    }

    return policyDigestOR;
}

ReadResult TPM::ReadPublic(ESYS_TR handle){
    TPM2_RC rc;
    ReadResult result;
    TPM2B_NAME *keyName;
    TPM2B_PUBLIC *keyPublic;
    TPM2B_NAME *keyQualifiedName;

    rc = Esys_ReadPublic(esys_context, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyPublic, &keyName, &keyQualifiedName);
    if (rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn´t retrieve the name of the key\n");
    }

    result.keyPublic = *keyPublic;
    result.keyName = *keyName;
    result.keyQualifiedName = *keyQualifiedName;

    Esys_Free(keyPublic);
    Esys_Free(keyName);
    Esys_Free(keyQualifiedName);

    return result;
}

int TPM::ExtendPcr(int pcr, const std::string &str, ESYS_TR session_handle) {

    TPM2B_DIGEST message = HashString(str, EVP_sha256());

    std::cout << "HASH: " << OPENSSL_buf2hexstr(message.buffer, message.size) << " \n";

    TPML_DIGEST_VALUES digests = {};
    digests.count = 1;
    digests.digests[0].hashAlg = TPM2_ALG_SHA256;
    memcpy(digests.digests[0].digest.sha256, message.buffer, message.size);

    TPM2_RC rc = Esys_PCR_Extend(esys_context, pcr, session_handle, ESYS_TR_NONE, ESYS_TR_NONE, &digests);

    return rc;
}

TSS2_RC TPM::GetDigest(ESYS_TR session_handle){
    TPM2B_DIGEST *policyDigest;

    TSS2_RC r = Esys_PolicyGetDigest(esys_context,
                             session_handle,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &policyDigest);

    if (r!=TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldnt get the policy digest\n");
        exit(-1);
    }

    std::cout << "PolicyDigest after PolicyPCR: " << OPENSSL_buf2hexstr(policyDigest->buffer, policyDigest->size) << "\n";

    return r;
}

int TPM::PolicyPCR_2(ESYS_TR pcr_handle, ESYS_TR session_handle, const std::vector<uint8_t> &digest){

    TPML_PCR_SELECTION pcrSelection;
    pcrSelection.count = 1;
    pcrSelection.pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcrSelection.pcrSelections[0].sizeofSelect = 3;
    pcrSelection.pcrSelections[0].pcrSelect[2] = 0x00;  // Clear the selection structure (optional if you start with a clean structure)
    pcrSelection.pcrSelections[0].pcrSelect[1] = 0x00;
    pcrSelection.pcrSelections[0].pcrSelect[0] = 0x00;
    pcrSelection.pcrSelections[0].pcrSelect[2] |= (1 << 7);

    TPM2B_DIGEST pcr_digest_zero;
    pcr_digest_zero.size = digest.size();
    std::copy(digest.begin(), digest.end(), pcr_digest_zero.buffer);

    TPM2B_DIGEST *policyDigest;

    TSS2_RC rc =  Esys_PolicyPCR(esys_context, session_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 &pcr_digest_zero, &pcrSelection);

    if (rc!=TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldnt execute the policyPCR function\n");
        exit(-1);
    }

    TSS2_RC r = Esys_PolicyGetDigest(esys_context,
                             session_handle,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &policyDigest);

    if (r!=TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldnt get the policy digest\n");
        exit(-1);
    }

    std::cout << "PolicyDigest after PolicyPCR: " << OPENSSL_buf2hexstr(policyDigest->buffer, policyDigest->size) << "\n";

    return rc;
}
