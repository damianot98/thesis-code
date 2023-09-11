//
// Created by damiano on 12/07/23.
//

#ifndef SEALING_TPM_H
#define SEALING_TPM_H

#include "tss2/tss2_esys.h"
#include "tss2/tss2_sys.h"
#include "structures.h"


class TPM {
public:
    TPM(int number);
    ~TPM();
    void Free(void *resourceObject);
    TSS2_RC FlushContext(uint32_t handle);
    CreatePrimaryResult CreatePrimary(int hierarchy, int type, int restricted, int decrypt,
                                      int sign, const std::string &unique,
                                      const std::string &user_auth,
                                      const std::string &sensitive_data,
                                      const std::vector<uint8_t> &auth_policy,
                                      int session_handle);
    CreatePrimaryResult CreatePrimaryCert(int hierarchy, int type, int restricted, int decrypt,
                                      int sign, const std::string &unique,
                                      const std::string &user_auth,
                                      const std::string &sensitive_data,
                                      const std::vector<uint8_t> &auth_policy,
                                      int session_handle);
    CreatePrimaryResult CreatePrimaryFromTemplate(ESYS_TR hierarchy,
                                                  const TPM2B_SENSITIVE_CREATE &in_sensitive,
                                                  const TPM2B_PUBLIC &in_public,
                                                  int session_handle);
    StartAuthSessionResult StartAuthSession(int session_type, bool is_symmetric, uint32_t handle);
    TPM2B_DIGEST* PolicyPCR(ESYS_TR pcrHandle, ESYS_TR sessionHandle, const std::vector<uint8_t> &digest);
    TPM2B_DIGEST* PolicyCMD(ESYS_TR session_handle);
    TPM2B_DIGEST* PolicyOR(ESYS_TR session_handle, TPML_DIGEST digest_list);
    CreateResult Create(uint32_t parent_handle, int type, int restricted,
                        int decrypt, int sign, const std::string &user_auth,
                        const std::string &sensitive_data,
                        const std::vector<uint8_t> &auth_policy,
                        int session_handle);
    CreateResult CreateWithAttributes(uint32_t parent_handle, int type, int restricted,
                        int decrypt, int sign, const std::string &user_auth,
                        const std::string &sensitive_data,
                        const std::vector<uint8_t> &auth_policy,
                        int session_handle);
    LoadResult Load(ESYS_TR parent_handle, const std::vector<uint8_t> &tpm2b_private, const std::vector<uint8_t> &tpm2b_public,
                    int session_handle);
    std::vector<uint8_t> EncryptRSAWithSession(uint32_t key_handle,
                                                    const std::vector<uint8_t> &message,
                                                    uint32_t session_handle);
    std::vector<uint8_t> DecryptRSAWithSession(uint32_t key_handle,
                                                    const std::vector<uint8_t> &message,
                                                    uint32_t session_handle);
    TPMS_CONTEXT* ContextSave(uint32_t key_handle);
    SignResult Sign(uint32_t key_handle, int type, const std::string &str, uint32_t session_handle);
    TPM2_RC VerifySignature(uint32_t key_handle, const std::string &str, const SignResult &in_signature, uint32_t session_handle);
    ReadResult ReadPublic(ESYS_TR handle);
    int ExtendPcr(int pcr, const std::string &str, ESYS_TR session_handle);
    TSS2_RC GetDigest(ESYS_TR session_handle);
    int PolicyPCR_2(ESYS_TR pcr_handle, ESYS_TR session_handle, const std::vector<uint8_t> &digest);

private:

    // Method to initialize the TCTI context
    void Init_Tcti_Tabrmd_Context();

    // Method to finalize the TCTI context
    void Finalize_Tcti_Tabrmd_Context();

    // Methods to initialize the ESYS context
    void Init_Esys_Context();

    // Method to finalize the ESYS context
    void Finalize_Esys_Context();

    int ErrorHandling(TSS2_RC rc);

private:
    TSS2_TCTI_CONTEXT *tcti_context = nullptr;
    ESYS_CONTEXT      *esys_context = nullptr;
    TSS2_SYS_CONTEXT *sys_context = nullptr;

    Key primaryKey;
    Key keyVM1;

    int identifier;
    TPMI_RH_NV_INDEX freeIndex;

    TSS2L_SYS_AUTH_COMMAND session_data_in;
    TSS2L_SYS_AUTH_RESPONSE session_data_out;


};


#endif //SEALING_TPM_H
