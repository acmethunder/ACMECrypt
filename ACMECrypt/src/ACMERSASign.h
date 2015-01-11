//
//  ACMERSASign.h
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2015-01-08.
//
//

#ifndef __ACMECrypt__ACMERSASign__
#define __ACMECrypt__ACMERSASign__

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>

#pragma mark - Validation

bool acme_supported_padding(SecPadding padding);

#pragma mark - Main Signing Function

CFDataRef acme_sign_data(CFDataRef data, SecPadding padding, SecKeyRef signKey);

#endif /* defined(__ACMECrypt__ACMERSASign__) */
