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

CFDataRef acme_sign_hash_data(CFDataRef hashData, SecPadding padding, CFDataRef rawData, SecKeyRef key);
CFDataRef acme_sha1_sign(CFDataRef data, SecKeyRef key);
CFDataRef acme_sha224_sign(CFDataRef data, SecKeyRef key);
CFDataRef acme_sha256_sign(CFDataRef data, SecKeyRef signKey);
CFDataRef acme_sha384_sign(CFDataRef data, SecKeyRef key);
CFDataRef acme_sha512_sign(CFDataRef data, SecKeyRef key);

#pragma mark - Main Verification Functions

bool acme_verify_hash_data(CFDataRef hashData, SecPadding padding, CFDataRef signature, SecKeyRef key);
bool acme_verify_sha1(CFDataRef rawData, CFDataRef signature, SecKeyRef key);
bool acme_verify_sha224(CFDataRef rawData, CFDataRef signature, SecKeyRef key);
bool acme_verify_sha256(CFDataRef rawData, CFDataRef signature, SecKeyRef signKey);
bool acme_verify_sha384(CFDataRef rawData, CFDataRef signature, SecKeyRef key);
bool acme_verify_sha512(CFDataRef rawData, CFDataRef signature, SecKeyRef key);

#endif /* defined(__ACMECrypt__ACMESign__) */
