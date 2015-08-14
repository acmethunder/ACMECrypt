//
//  ACMERSASign.c
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2015-01-08.
//
//

#include "ACMESign.h"

#include "ACMEHash.h"

///*
//enum
//{
//    kSecPaddingNone      = 0,
//    kSecPaddingPKCS1     = 1,
//    kSecPaddingOAEP      = 2,
//    
//    /* For SecKeyRawSign/SecKeyRawVerify only, data to be signed is an MD2
//     hash; standard ASN.1 padding will be done, as well as PKCS1 padding
//     of the underlying RSA operation. */
//    //kSecPaddingPKCS1MD2  = 0x8000,  /* Unsupported as of iOS 5.0 */
//    
//    /* For SecKeyRawSign/SecKeyRawVerify only, data to be signed is an MD5
//     hash; standard ASN.1 padding will be done, as well as PKCS1 padding
//     of the underlying RSA operation. */
//    //kSecPaddingPKCS1MD5  = 0x8001,  /* Unsupported as of iOS 5.0 */
//    
//    /* For SecKeyRawSign/SecKeyRawVerify only, data to be signed is a SHA1
//     hash; standard ASN.1 padding will be done, as well as PKCS1 padding
//     of the underlying RSA operation. */
//    //kSecPaddingPKCS1SHA1 = 0x8002,
//    
//    /* For SecKeyRawSign/SecKeyRawVerify only, data to be signed is a SHA224
//     hash; standard ASN.1 padding will be done, as well as PKCS1 padding
//     of the underlying RSA operation. */
//    //kSecPaddingPKCS1SHA224 = 0x8003,
//    
//    /* For SecKeyRawSign/SecKeyRawVerify only, data to be signed is a SHA256
//     hash; standard ASN.1 padding will be done, as well as PKCS1 padding
//     of the underlying RSA operation. */
//    //kSecPaddingPKCS1SHA256 = 0x8004,
//    
//    /* For SecKeyRawSign/SecKeyRawVerify only, data to be signed is a SHA384
//     hash; standard ASN.1 padding will be done, as well as PKCS1 padding
//     of the underlying RSA operation. */
//    //kSecPaddingPKCS1SHA384 = 0x8005,
//    
//    /* For SecKeyRawSign/SecKeyRawVerify only, data to be signed is a SHA512
//     hash; standard ASN.1 padding will be done, as well as PKCS1 padding
//     of the underlying RSA operation. */
//    //kSecPaddingPKCS1SHA512 = 0x8006,
//};

bool acme_supported_padding(SecPadding padding) {
    bool isGood;
    
    switch ( padding ) {
        case kSecPaddingPKCS1SHA1   :
        case kSecPaddingPKCS1SHA224 :
        case kSecPaddingPKCS1SHA256 :
        case kSecPaddingPKCS1SHA384 :
        case kSecPaddingPKCS1SHA512 :
            isGood = true;
            break;
        case kSecPaddingNone     :
        case kSecPaddingPKCS1    :
        case kSecPaddingOAEP     :
        case kSecPaddingPKCS1MD2 :
        case kSecPaddingPKCS1MD5 :
        default                  :
            isGood = false;
            break;
    }
    
    return isGood;
}

CFDataRef acme_sign_hash_data(CFDataRef hashData, SecPadding padding, CFDataRef rawData, SecKeyRef key) {
    CFDataRef signature = NULL;

    if ( hashData && acme_supported_padding(padding) && rawData && key ) {
        const void *hashBytes = CFDataGetBytePtr(hashData);
        size_t hashLength = CFDataGetLength(hashData);

        size_t signatureSize = SecKeyGetBlockSize(key);
        void *signatureBytes = malloc(signatureSize);
        memset(signatureBytes, 0, signatureSize);

        OSStatus status = SecKeyRawSign(
                                        key,
                                        padding,
                                        hashBytes,
                                        hashLength,
                                        signatureBytes,
                                        &signatureSize );

        if ( status == errSecSuccess ) {
            signature = CFDataCreate( kCFAllocatorDefault, signatureBytes, (CFIndex)signatureSize );
        }
    }

    return signature;
}

CFDataRef acme_sha1_sign(CFDataRef data, SecKeyRef key) {
    CFDataRef hashData = ( key ? ACMHash(data, ACMHashAlgSHA1) : NULL );

    CFDataRef signature;
    if ( hashData ) {
        signature = acme_sign_hash_data(
                                        hashData,
                                        kSecPaddingPKCS1SHA1,
                                        data,
                                        key );
        CFRelease(hashData);
    }
    else {
        signature = NULL;
    }

    return signature;
}

CFDataRef acme_sha224_sign(CFDataRef data, SecKeyRef key) {
    CFDataRef hashData = ( key ? ACMHash(data, ACMHashAlgSHA224) : NULL );

    CFDataRef signature;
    if ( hashData ) {
        signature = acme_sign_hash_data(
                                        hashData,
                                        kSecPaddingPKCS1SHA224,
                                        data,
                                        key );
        CFRelease(hashData);
    }
    else {
        signature = NULL;
    }

    return signature;

}

CFDataRef acme_sha256_sign(CFDataRef data, SecKeyRef key) {
    CFDataRef hashData = ( key ? ACMHash(data, ACMHashAlgSHA256) : NULL );

    CFDataRef signature;
    if ( hashData ) {
        signature = acme_sign_hash_data(
                                        hashData,
                                        kSecPaddingPKCS1SHA256,
                                        data,
                                        key );
        CFRelease(hashData);
    }
    else {
        signature = NULL;
    }

    return signature;
}

CFDataRef acme_sha384_sign(CFDataRef data, SecKeyRef key) {
    CFDataRef hashData = ( key ? ACMHash(data, ACMHashAlgSHA384) : NULL );

    CFDataRef signature;
    if ( hashData ) {
        signature = acme_sign_hash_data(
                                        hashData,
                                        kSecPaddingPKCS1SHA384,
                                        data,
                                        key );
        CFRelease(hashData);
    }
    else {
        signature = NULL;
    }

    return signature;
}

CFDataRef acme_sha512_sign(CFDataRef data, SecKeyRef key) {
    CFDataRef hashData = ( key ? ACMHash(data, ACMHashAlgSHA512) : NULL );

    CFDataRef signature;
    if ( hashData ) {
        signature = acme_sign_hash_data(
                                        hashData,
                                        kSecPaddingPKCS1SHA512,
                                        data,
                                        key );
        CFRelease(hashData);
    }
    else {
        signature = NULL;
    }

    return signature;
}

bool acme_verify_hash_data(CFDataRef hashData, SecPadding padding, CFDataRef signature, SecKeyRef key) {
    bool verified = false;

    if ( hashData && acme_supported_padding(padding) && signature && key ) {
        const uint8_t *hashBytes = CFDataGetBytePtr(hashData);
        size_t hashLength = (size_t)CFDataGetLength(hashData);

        const uint8_t *signatureBytes = CFDataGetBytePtr(signature);
        size_t signatureLength = CFDataGetLength(signature);

        OSStatus status = SecKeyRawVerify(
                                          key,
                                          padding,
                                          hashBytes,
                                          hashLength,
                                          signatureBytes,
                                          signatureLength );

        verified = ( status == errSecSuccess );
    }

    return verified;
}

bool acme_verify_sha1(CFDataRef rawData, CFDataRef signature, SecKeyRef key) {
    CFDataRef hash = ( (signature && key) ? ACMHash(rawData, ACMHashAlgSHA1) : NULL );

    bool verified;
    if ( hash ) {
        verified = acme_verify_hash_data(hash, kSecPaddingPKCS1SHA1, signature, key);
        CFRelease(hash);
    }
    else {
        verified = false;
    }

    return verified;
}

bool acme_verify_sha224(CFDataRef rawData, CFDataRef signature, SecKeyRef key) {
    CFDataRef hash = ( (signature && key) ? ACMHash(rawData, ACMHashAlgSHA224) : NULL );

    bool verified;
    if ( hash ) {
        verified = acme_verify_hash_data(hash, kSecPaddingPKCS1SHA224, signature, key);
        CFRelease(hash);
    }
    else {
        verified = false;
    }

    return verified;
}

bool acme_verify_sha256(CFDataRef rawData, CFDataRef signature, SecKeyRef key) {
    CFDataRef hash = ( (signature && key) ? ACMHash(rawData, ACMHashAlgSHA256) : NULL );

    bool verified;
    if ( hash ) {
        verified = acme_verify_hash_data(hash, kSecPaddingPKCS1SHA256, signature, key);
        CFRelease(hash);
    }
    else {
        verified = false;
    }

    return verified;
}

bool acme_verify_sha384(CFDataRef rawData, CFDataRef signature, SecKeyRef key) {
    CFDataRef hash = ( (signature && key) ? ACMHash(rawData, ACMHashAlgSHA384) : NULL );

    bool verified;
    if ( hash ) {
        verified = acme_verify_hash_data(hash, kSecPaddingPKCS1SHA384, signature, key);
        CFRelease(hash);
    }
    else {
        verified = false;
    }

    return verified;
}

bool acme_verify_sha512(CFDataRef rawData, CFDataRef signature, SecKeyRef key) {
    CFDataRef hash = ( (signature && key) ? ACMHash(rawData, ACMHashAlgSHA512) : NULL );

    bool verified;
    if ( hash ) {
        verified = acme_verify_hash_data(hash, kSecPaddingPKCS1SHA512, signature, key);
        CFRelease(hash);
    }
    else {
        verified = false;
    }

    return verified;
}
