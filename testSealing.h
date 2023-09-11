//
// Created by damiano on 12/07/23.
//

#ifndef SEALING_TESTSEALING_H
#define SEALING_TESTSEALING_H

#include "TPM.h"

void TestSealing(TPM *tpm);
void TestSigningWithSealedRSAKey(TPM *tpm);
void TestCertifyX509(TPM *tpm);
void TestMigrateRSAKey(TPM *tpm);

#endif //SEALING_TESTSEALING_H
