//
//  ACMEHash.c
//  ACMECrypt
//
//  Created by Mike De Wolfe on 2014-04-04.
//
//

#include <CommonCrypto/CommonHMAC.h>

#include "ACMEHash.h"

//CFDataRef ACGetMD5(CFDataRef data) {
//	CFDataRef final = NULL;
//    CFIndex length = ( data ? CFDataGetLength(data) : 0 );
//    if ( length > 0 ) {
//        const char *plainText = (char*)CFDataGetBytePtr(data);
//        unsigned char digest[CC_MD5_DIGEST_LENGTH];
//        
//        CC_MD5(plainText, (unsigned int)length, digest);
//		
//		final = CFDataCreate(kCFAllocatorDefault, digest, CC_MD5_DIGEST_LENGTH);
//    }
//    
//    return final;
//}
//
//CFDataRef ACGetSHA1(CFDataRef data) {
//	CFDataRef final = NULL;
//	CFIndex dataLength = ( data ? CFDataGetLength(data) : 0 );
//	
//	if ( dataLength > 0 ) {
//		const char *plain = (char*)CFDataGetBytePtr(data);
//		unsigned char digest[CC_SHA1_DIGEST_LENGTH];
//		
//		CC_SHA1(plain, (unsigned int)dataLength, digest);
//		final = CFDataCreate(kCFAllocatorDefault, digest, CC_SHA1_DIGEST_LENGTH);
//	}
//	
//	return  final;
//}
//
//CFDataRef ACGetSHA224(CFDataRef data) {
//	CFDataRef final = NULL;
//	
//	CFIndex length = ( data ? CFDataGetLength(data) : 0 );
//	if ( length > 0 ) {
//		const char *plain = (char*)CFDataGetBytePtr(data);
//		unsigned char digest[CC_SHA224_DIGEST_LENGTH];
//		
//		CC_SHA224(plain, (unsigned int)length, digest);
//		final = CFDataCreate(kCFAllocatorDefault, digest, CC_SHA224_DIGEST_LENGTH);
//	}
//	
//	return final;
//}
//
//CFDataRef ACGetSHA256(CFDataRef data) {
//	CFDataRef final = NULL;
//	CFIndex length = ( data ? CFDataGetLength(data) : 0 );
//	
//	if ( length > 0 ) {
//		const char *plain = (char*)CFDataGetBytePtr(data);
//		unsigned char digest[CC_SHA256_DIGEST_LENGTH];
//		CC_SHA256(plain, (unsigned int)length, digest);
//        
//		final = CFDataCreate(kCFAllocatorDefault, digest, CC_SHA256_DIGEST_LENGTH);
//	}
//	
//	return final;
//}
//
//CFDataRef ACGetSHA384(CFDataRef data) {
//	CFDataRef final = NULL;
//	CFIndex length = ( data ? CFDataGetLength(data) : 0 );
//	
//	if ( length > 0 ) {
//		const char *plainptr = (char*)CFDataGetBytePtr(data);
//		unsigned char digest[CC_SHA384_DIGEST_LENGTH];
//		CC_SHA384(plainptr, (unsigned int)length, digest);
//		
//		final = CFDataCreate(kCFAllocatorDefault, digest, CC_SHA384_DIGEST_LENGTH);
//	}
//	
//	return final;
//}
//
//CFDataRef ACGetSHA512(CFDataRef data) {
//	CFDataRef final = NULL;
//	CFIndex length = ( data ? CFDataGetLength(data) : 0 );
//	
//	if ( length > 0 ) {
//		const char *plainptr = (char*)CFDataGetBytePtr(data);
//		unsigned char digest[CC_SHA512_DIGEST_LENGTH];
//		CC_SHA512(plainptr, (unsigned int)length, digest);
//		
//		final = CFDataCreate(kCFAllocatorDefault, digest, CC_SHA512_DIGEST_LENGTH);
//	}
//	
//	return final;
//}

CFDataRef ACMHash(CFDataRef data, ACMHashAlg alg) {
    CFDataRef final = NULL;
    CFIndex length = ( data ? CFDataGetLength(data) : 0 );
    
    if ( length > 0 ) {
        size_t digestLength = 0;
        unsigned char* (*hashFunc)(const void*,CC_LONG,unsigned char*) = NULL;
        switch (alg) {
            case ACMHashAlgSHA1:
                digestLength = CC_SHA1_DIGEST_LENGTH;
                hashFunc = CC_SHA1;
                break;
            case ACMHashAlgSHA224:
                digestLength = CC_SHA224_DIGEST_LENGTH;
                hashFunc = CC_SHA224;
                break;
            case ACMHashAlgSHA256:
                digestLength = CC_SHA256_DIGEST_LENGTH;
                hashFunc = CC_SHA256;
                break;
            case ACMHashAlgSHA384:
                digestLength = CC_SHA384_DIGEST_LENGTH;
                hashFunc = CC_SHA384;
                break;
            case ACMHashAlgSHA512:
                digestLength = CC_SHA512_DIGEST_LENGTH;
                hashFunc = CC_SHA512;
                break;
            case ACMHashAlgMD5:
            default:
                digestLength = CC_MD2_DIGEST_LENGTH;
                hashFunc = CC_MD5;
                break;
        }
        
        const char *plaintptr = (char*)CFDataGetBytePtr(data);
        unsigned char *digest = malloc(digestLength);
        memset(digest, 0, digestLength);
        
        hashFunc( plaintptr, (CC_LONG)length, digest );
        
        final = CFDataCreate(kCFAllocatorDefault, digest, digestLength);
        
        free(digest);
    }
    
    
    return final;
}

