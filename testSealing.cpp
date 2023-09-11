//
// Created by damiano on 12/07/23.
//

#include "testSealing.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <cstring>

#define DEBUG false

using namespace std;

vector<uint8_t> readFileToVector(const string& filename) {
    vector<uint8_t> data;

    // Open the file for binary input
    ifstream file(filename, ios::binary);

    if (!file) {
        cerr << "Error opening file: " << filename << endl;
        return data; // Return an empty vector if file opening fails
    }

    // Get the size of the file
    file.seekg(0, ios::end);
    streampos fileSize = file.tellg();
    file.seekg(0, ios::beg);

    // Resize the vector to fit the file's content
    data.resize(fileSize);

    // Read the file content into the vector
    file.read(reinterpret_cast<char*>(data.data()), fileSize);

    // Close the file
    file.close();

    return data;
}

void writeFileFromVector(const std::string& filename, const std::vector<uint8_t>& data) {
    // Open the file for output in text mode
    std::ofstream file(filename);

    if (!file) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    // Write the content of the vector to the file as characters
    for (uint8_t byte : data) {
        file.put(static_cast<char>(byte));
    }

    // Close the file
    file.close();
}

void writeFileInBinary(const std::string& filename, const std::vector<uint8_t>& data) {
    // Open the file for output in text mode
    std::ofstream file(filename, ios::binary);

    if (!file) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());

    // Close the file
    file.close();
}

string uint8_vector_to_hex_string(const vector<uint8_t>& v)
{
    string result;
    result.reserve(v.size() * 2);   // two digits per character

    static constexpr char hex[] = "0123456789abcdef";

    for (uint8_t c : v)
    {
        result.push_back(hex[c / 16]);
        result.push_back(hex[c % 16]);
    }

    return result;
}


void TestSealing(TPM *tpm) {

    const string fileInput = "/home/damiano/Desktop/test/outputs/file.txt";
    const string fileEncrypted = "/home/damiano/Desktop/test/outputs/file.enc";
    const string fileDecrypted = "/home/damiano/Desktop/test/outputs/file.dec";

    // Read the file and store the content in a vector
    vector<uint8_t> fileData = readFileToVector(fileInput);

    // Start HMAC session
    StartAuthSessionResult temporarySession = tpm->StartAuthSession(3, true, ESYS_TR_NONE);

    // Create Primary Key
    CreatePrimaryResult pk = tpm->CreatePrimary(ESYS_TR_RH_OWNER, TPM2_ALG_RSA, 1, 1, 0, "", "","", vector<uint8_t>(), temporarySession.handle);

    if (pk.rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn't create the primary key\n");
        exit(-2);
    }

    StartAuthSessionResult policySession = tpm->StartAuthSession(2, true, ESYS_TR_NONE);
    TPM2B_DIGEST *policyDigest = tpm->PolicyPCR(23, policySession.handle, vector<uint8_t>());
    vector<uint8_t> digest = vector<uint8_t>(policyDigest->buffer, policyDigest->buffer+policyDigest->size);
    CreateResult key = tpm->Create(pk.handle, TPM2_ALG_RSA, 0, 1, 1, "", "", digest, temporarySession.handle);

    if (key.rc!=TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn't create the child key\n");
        exit(-3);
    }

    LoadResult load_key;

    load_key = tpm->Load(pk.handle, key.tpm2b_private, key.tpm2b_public, temporarySession.handle);

    if (load_key.rc!=TPM2_RC_SUCCESS){
        fprintf(stderr, "error loading the key\n");
    }else{
        fprintf(stdout, "Loaded successfully\n");
    }

    vector<uint8_t> encrypted_message;

    if (fileData.empty()) {
        cout << "Failed to read the file or file is empty." << endl;
    } else {
        cout << "data to encrypt: " << uint8_vector_to_hex_string(fileData) << "\n";

        encrypted_message = tpm->EncryptRSAWithSession(load_key.handle, fileData, temporarySession.handle);

        cout << "data encrypted: " << uint8_vector_to_hex_string(encrypted_message) << "\n";

//        tpm->ExtendPcr(23, "Test", temporarySession.handle);

        vector<uint8_t> decrypted_message = tpm->DecryptRSAWithSession(load_key.handle, encrypted_message, policySession.handle);

        cout << "data decrypted: " << uint8_vector_to_hex_string(decrypted_message) << "\n";

        writeFileFromVector(fileEncrypted, encrypted_message);
        writeFileFromVector(fileDecrypted, decrypted_message);
    }

//    tpm->FlushContext(policySession.handle);


//    tpm->ExtendPcr(23, "Test", temporarySession.handle);
//    policySession = tpm->StartAuthSession(2, true, ESYS_TR_NONE);
//    if(tpm->PolicyPCR_2(23, policySession.handle, vector<uint8_t>())!=TPM2_RC_SUCCESS){
//        fprintf(stderr, "Couldn't execute the policyPCR function\n");
//    }
//    if (tpm->GetDigest(policySession.handle)!=TPM2_RC_SUCCESS){
//        fprintf(stderr, "Couldn't retrieve the digest\n");
//    }
//
//    cout << "data to encrypt wrong digest: " << uint8_vector_to_hex_string(fileData) << "\n";
//
//    vector<uint8_t> decrypted_message_wrong = tpm->DecryptRSAWithSession(load_key.handle, encrypted_message, policySession.handle);
//
//    cout << "data decrypted: " << uint8_vector_to_hex_string(decrypted_message_wrong) << "\n";

    tpm->FlushContext(temporarySession.handle);
    tpm->FlushContext(policySession.handle);

}

void TestSigningWithSealedRSAKey(TPM *tpm){

    TPM2B_NAME *name;
    LoadResult result;
    vector<uint8_t> pk1_name;

    // Start HMAC session
    StartAuthSessionResult temporarySession = tpm->StartAuthSession(3, true, ESYS_TR_NONE);

    // Create Primary Key
    CreatePrimaryResult pk = tpm->CreatePrimary(ESYS_TR_RH_ENDORSEMENT, TPM2_ALG_RSA, 1, 1, 0, "", "","", vector<uint8_t>(), temporarySession.handle);

    if (pk.rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Could not create the primary key\n");
    }else{
        std::cout << "rc: "<<pk.rc <<"\thandle: "<<pk.handle << "\trsa_public_n: " << uint8_vector_to_hex_string(pk.rsa_public_n) << "\n";
    }

    StartAuthSessionResult policySession = tpm->StartAuthSession(2, true, ESYS_TR_NONE);
    TPM2B_DIGEST *policyDigest = tpm->PolicyPCR(23, policySession.handle, vector<uint8_t>());
    vector<uint8_t> digest = vector<uint8_t>(policyDigest->buffer, policyDigest->buffer+policyDigest->size);
    CreateResult key = tpm->Create(pk.handle, TPM2_ALG_RSA, 0, 1, 1, "", "", digest, temporarySession.handle);

    if (key.rc!=TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn't create the child key\n");
        exit(-3);
    }

    LoadResult load_key;

    load_key = tpm->Load(pk.handle, key.tpm2b_private, key.tpm2b_public, temporarySession.handle);

    if (load_key.rc!=TPM2_RC_SUCCESS){
        fprintf(stderr, "error loading the key\n");
    }else{
        fprintf(stdout, "Loaded successfully\n");
    }

    SignResult signatureResult = tpm->Sign(load_key.handle, TPM2_ALG_RSA, "Hello", policySession.handle);

    if (signatureResult.rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Could not sign the message\n");
    }else{
        std::cout << "rsa_ssa_sig: " << uint8_vector_to_hex_string(signatureResult.rsa_ssa_sig) << "\n";
    }

    signatureResult.rc = tpm->VerifySignature(load_key.handle, "Hello", signatureResult, temporarySession.handle);

    if (signatureResult.rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Error when verifying the signature\n");
    }else{
        fprintf(stdout, "Signature successfully verified\n");
    }

    if (tpm->FlushContext(load_key.handle) != TPM2_RC_SUCCESS){
        fprintf(stderr, "Could not flush the primary key from the memory\n");
    }else{
        fprintf(stdout, "Primary Key successfully flushed\n");
    }
    tpm->FlushContext(temporarySession.handle);
    tpm->FlushContext(policySession.handle);
}

//This requires mssim >= v1628
//tpm:parameter(2):reserved bits not set to zero as required
void TestCertifyX509(TPM *tpm){
    const string filePartialCertificate = "/home/damiano/Desktop/test/partial_cert.der";

    // Read the file and store the content in a vector
    vector<uint8_t> fileData = readFileToVector(filePartialCertificate);

    if (fileData.empty()) {
        cout << "Failed to read the file or file is empty." << endl;
        exit(-1);
    } else {
        TPM2B_MAX_BUFFER partialCertificate;
        partialCertificate.size = fileData.size();
        memcpy(partialCertificate.buffer, fileData.data(), fileData.size());
    }

    // Compute the policy digest
    StartAuthSessionResult temporarySession = tpm->StartAuthSession(3, false, ESYS_TR_NONE);

    // Create Primary Key
    CreatePrimaryResult pk = tpm->CreatePrimaryCert(ESYS_TR_RH_OWNER, TPM2_ALG_RSA, 1, 0, 1, "", "","", vector<uint8_t>(), ESYS_TR_PASSWORD);

//    if (pk.rc != TPM2_RC_SUCCESS){
//        fprintf(stderr, "Couldn't create the primary key\n");
//        exit(-2);
//    }
//
//    StartAuthSessionResult policySession = tpm->StartAuthSession(2, true, ESYS_TR_NONE);
//    TPM2B_DIGEST *policyDigest = tpm->PolicyPCR(23, policySession.handle, vector<uint8_t>());
//    vector<uint8_t> digest = vector<uint8_t>(policyDigest->buffer, policyDigest->buffer+policyDigest->size);
//    CreateResult key = tpm->Create(pk.handle, TPM2_ALG_RSA, 0, 1, 1, "", "", digest, temporarySession.handle);
//
//    if (key.rc!=TPM2_RC_SUCCESS){
//        fprintf(stderr, "Couldn't create the child key\n");
//        exit(-3);
//    }
//
//    LoadResult load_key;
//
//    load_key = tpm->Load(pk.handle, key.tpm2b_private, key.tpm2b_public, temporarySession.handle);
//
//    if (load_key.rc!=TPM2_RC_SUCCESS){
//        fprintf(stderr, "error loading the key\n");
//    }else{
//        fprintf(stdout, "Loaded successfully\n");
//    }
    tpm->FlushContext(temporarySession.handle);
}

void TestMigrateRSAKey(TPM *tpm){

    // On TPM-B
    // 1) Create a primary key
    // 2) Create a child key with these attributes "restricted|sensitivedataorigin|decrypt|userwithauth"
    // 3) Copy the public part of the key just created to the TPM-A

    // Start HMAC session
    StartAuthSessionResult temporarySession = tpm->StartAuthSession(3, true, ESYS_TR_NONE);
#if DEBUG
    /// 1)
    CreatePrimaryResult pk0 = tpm->CreatePrimary(ESYS_TR_RH_OWNER, TPM2_ALG_RSA, 1, 1, 0, "", "","", vector<uint8_t>(), temporarySession.handle);

    if (pk0.rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn't create the primary key\n");
        exit(-2);
    }

    /// 2)
    CreateResult key0 = tpm->CreateWithAttributes(pk0.handle, TPM2_ALG_RSA, 1, 1, 0, "", "", vector<uint8_t>(), temporarySession.handle);

    if (key0.rc!=TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn't create the child key\n");
        exit(-3);
    }

    /// 3)
    std::vector<uint8_t> parentPub(key0.tpm2b_public);
#endif
    // Flush the HMAC session
    tpm->FlushContext(temporarySession.handle);

    // On TPM-A
    // 1) Create a root object
    // 2) Create an auth policy that allows duplication and dependent of PCRs
    // 3) Generate an RSA keypair depending on the policyPCR (it will be duplicated)
    // 4) Load the public part of the key copied from the TPM-B
    // 5) Duplicate

    // Start HMAC session
    temporarySession = tpm->StartAuthSession(3, true, ESYS_TR_NONE);

    /// 2)
    CreatePrimaryResult pk1 = tpm->CreatePrimary(ESYS_TR_RH_OWNER, TPM2_ALG_RSA, 1, 1, 0, "", "","", vector<uint8_t>(), temporarySession.handle);

    if (pk1.rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn't create the primary key\n");
        exit(-2);
    }

    StartAuthSessionResult policySession = tpm->StartAuthSession(2, true, ESYS_TR_NONE);

    TPM2B_DIGEST *policyDigestPCR = tpm->PolicyPCR(23, policySession.handle, vector<uint8_t>());
    TPM2B_DIGEST *policyDigestCMD = tpm->PolicyCMD(policySession.handle);

    TPML_DIGEST policyDigestList = {
            .count = 2,
            .digests = {
                    *policyDigestPCR,
                    *policyDigestCMD
            }
    };

    TPM2B_DIGEST *policyDigestOR = tpm->PolicyOR(policySession.handle, policyDigestList);

    cout << "PolicyDigestPCR: " << uint8_vector_to_hex_string(vector<uint8_t>(policyDigestPCR->buffer, policyDigestPCR->buffer+policyDigestPCR->size)) << "\n";

    cout << "PolicyDigestCMD: " << uint8_vector_to_hex_string(vector<uint8_t>(policyDigestCMD->buffer, policyDigestCMD->buffer+policyDigestCMD->size)) << "\n";

    cout << "PolicyDigestOR: " << uint8_vector_to_hex_string(vector<uint8_t>(policyDigestOR->buffer, policyDigestOR->buffer+policyDigestOR->size)) << "\n";

    vector<uint8_t> digest = vector<uint8_t>(policyDigestOR->buffer, policyDigestOR->buffer+policyDigestOR->size);


    CreateResult key1 = tpm->CreateWithAttributes(pk1.handle, TPM2_ALG_RSA, 0, 1, 1, "", "", digest, temporarySession.handle);

    if (key1.rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn't create the child key\n");
    }

    tpm->FlushContext(policySession.handle);

    LoadResult loadKey = tpm->Load(pk1.handle, key1.tpm2b_private, key1.tpm2b_public, temporarySession.handle);

    if (loadKey.rc != TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldn't load the child key\n");
    }else{
        fprintf(stdout, "Key successfully loaded\n");
    }

    vector<uint8_t> message{'t', 'e', 's', 't', '\n'};

    vector<uint8_t> messageEncrypted = tpm->EncryptRSAWithSession(loadKey.handle, message, temporarySession.handle);
    cout << "Message Encrypted: " << uint8_vector_to_hex_string(messageEncrypted) << "\n";

    StartAuthSessionResult policySession2 = tpm->StartAuthSession(3, true, ESYS_TR_NONE);

    TPM2B_DIGEST *policyDigestPCR2 = tpm->PolicyPCR(23, policySession2.handle, vector<uint8_t>());
//    TPM2B_DIGEST *policyDigestCMD2 = tpm->PolicyCMD(policySession2.handle);
//
//    TPML_DIGEST policyDigestList2 = {
//            .count = 2,
//            .digests = {
//                    *policyDigestPCR2,
//                    *policyDigestCMD2
//            }
//    };
//
//    TPM2B_DIGEST *policyDigestOR2 = tpm->PolicyOR(policySession2.handle, policyDigestList2);

    vector<uint8_t> messageDecrypted = tpm->DecryptRSAWithSession(loadKey.handle, messageEncrypted, policySession2.handle);
    cout << "Message Decrypted: " << uint8_vector_to_hex_string(messageDecrypted) << "\n";


    ReadResult readResult = tpm->ReadPublic(loadKey.handle);

    cout << "KeyName: " << uint8_vector_to_hex_string(vector<uint8_t>(readResult.keyName.name, readResult.keyName.name+readResult.keyName.size )) << "\n";

    cout << "KeyQualifiedName: " << uint8_vector_to_hex_string(vector<uint8_t>(readResult.keyQualifiedName.name, readResult.keyQualifiedName.name+readResult.keyQualifiedName.size )) << "\n";


    tpm->FlushContext(temporarySession.handle);
    tpm->FlushContext(policySession.handle);
    tpm->FlushContext(loadKey.handle);

}

