#include <iostream>
#include "testSealing.h"

int main() {

    TSS2_RC rc;

    TPM tpm(2);

    TestSealing(&tpm);

//    TestSigningWithSealedRSAKey(&tpm);

//    TestCertifyX509(&tpm);

//    TestMigrateRSAKey(&tpm);

    return 0;
}
