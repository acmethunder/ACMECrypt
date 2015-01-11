//
//  ACMERSASign.c
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2015-01-08.
//
//

#include "ACMERSASign.h"
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
        case kSecPaddingNone        :
        case kSecPaddingPKCS1       :
        case kSecPaddingOAEP        :
        case kSecPaddingPKCS1SHA1   :
        case kSecPaddingPKCS1SHA224 :
        case kSecPaddingPKCS1SHA256 :
        case kSecPaddingPKCS1SHA384 :
        case kSecPaddingPKCS1SHA512 : isGood = true;
            break;
        case kSecPaddingPKCS1MD2 :
        case kSecPaddingPKCS1MD5 :
        default                  : isGood = false;
            break;
    }
    
    return isGood;
}

CFDataRef acme_sign_data(CFDataRef data, SecPadding padding, SecKeyRef signKey) {
    CFDataRef finalData = NULL;
    
    CFIndex dataLength = ( data != NULL ? CFDataGetLength(data) : 0 );
    
    if ( (signKey != NULL) && (dataLength > 0) && acme_supported_padding(padding) ) {
        size_t keySize = SecKeyGetBlockSize(signKey);
        
        size_t finalRawLength;
        if ( padding == kSecPaddingPKCS1 ) {
            finalRawLength = dataLength - keySize - 11;
        }
        else {
            finalRawLength = (size_t)dataLength;
        }
        
        const uint8_t *rawBytes = CFDataGetBytePtr(data);
        uint8_t *signBytes = malloc(keySize);
        OSStatus status =  SecKeyRawSign(
                                         signKey,
                                         padding,
                                         rawBytes,
                                         finalRawLength,
                                         signBytes,
                                         &keySize );
        if ( status == errSecSuccess ) {
            size_t signLength;
            switch ( padding ) {
                case kSecPaddingPKCS1SHA256 : signLength = CC_SHA256_DIGEST_LENGTH;
                    break;
                default: signLength = 0;
                    break;
            }

            finalData = CFDataCreate(kCFAllocatorDefault, signBytes, (CFIndex)signLength);
        }
        
        if ( signBytes ) {
            free(signBytes);
        }
    }
    
    
    return finalData;
}

bool acme_verify_signature(CFDataRef signedData, CFDataRef hashData, SecPadding padding, SecKeyRef publicKey) {
    bool isgood;
    
    CFIndex signLength = ( signedData ? CFDataGetLength(signedData) : 0 );
    CFIndex hashLength = ( hashData ? CFDataGetLength(hashData) : 0 );
    if ( (hashData > 0) && (signLength > 0) && publicKey && acme_supported_padding(padding) ) {
        
        const uint8_t *hashBytes   = CFDataGetBytePtr(hashData);
        const uint8_t *signedBytes = CFDataGetBytePtr(signedData);
        OSStatus status = SecKeyRawVerify(
                                          publicKey,
                                          padding,
                                          hashBytes,
                                          (size_t)hashLength,
                                          signedBytes,
                                          (size_t)signLength );
        
        isgood = ( status == errSecSuccess );
    }
    else {
        isgood = false;
    }
    
    
    
    return isgood;
}
