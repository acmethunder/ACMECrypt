//
//  ACMESymmetric.c
//  ACMECrypt
//
//  Created by Mike De Wolfe on 2014-04-04.
//
//

#include "ACMESymmetric.h"

CFDataRef ACMEncryptAES256(CFDataRef data, CFStringRef key, CFStringRef initVector) {
    CFDataRef final = NULL;
    
    CFIndex dataLength = ( data ? CFDataGetLength(data) : (CFIndex)0 );
    CFIndex keyLength  = ( key ? CFStringGetLength(key) : (CFIndex)0 );
    CFIndex ivLength   = ( initVector ? CFStringGetLength(initVector) : (CFIndex)0 );
    
    if ( (dataLength > 0) && (keyLength > 0) && (ivLength > 0) ) {
		const char *ivptr = CFStringGetCStringPtr(initVector, kCFStringEncodingUTF8);
        
		if ( ivptr ) {
            char keyptr[kCCKeySizeAES256];
            memset(keyptr, 0, sizeof(keyptr));
            
            if ( CFStringGetCString(key, keyptr, kCCKeySizeAES256, kCFStringEncodingUTF8) ) {
                size_t buffersize = dataLength + kCCBlockSizeAES128;
                size_t bytesencrypted = 0;
                
                void *cipherbuffer = malloc(buffersize);
                const char *plainBuffer = (char*)CFDataGetBytePtr(data);
                
                CCCryptorStatus status = CCCrypt(
                                                 kCCEncrypt,
                                                 kCCAlgorithmAES128,
                                                 kCCOptionPKCS7Padding,
                                                 keyptr,
                                                 kCCKeySizeAES256,
                                                 ivptr,
                                                 plainBuffer,
                                                 dataLength,
                                                 cipherbuffer,
                                                 buffersize,
                                                 &bytesencrypted );
                
                if ( status == kCCSuccess ) {
                    final = CFDataCreate(kCFAllocatorDefault, cipherbuffer, bytesencrypted);
                }
                
                free(cipherbuffer);
            }
        }
    }
    
    
    return final;
}

CFDataRef ACMDecryptAES256(CFDataRef data, CFStringRef key, CFStringRef initVector) {
	CFDataRef final = 0;
	
	CFIndex dataLength = ( data ? CFDataGetLength(data) : 0 );
	CFIndex keyLength  = ( key ? CFStringGetLength(key) : 0 );
	CFIndex ivLength   = ( initVector ? CFStringGetLength(initVector) : 0 );
	
	if ( (dataLength > 0) && (keyLength > 0) && (ivLength > 0) ) {
		const char *ivptr = CFStringGetCStringPtr(initVector, kCFStringEncodingUTF8);
		
		if ( ivptr ) {
            
            char keyPtr[kCCKeySizeAES256];	// 'key' should be 32 bytes for AES256, will be null-padded otherwise
            memset(keyPtr, 0, sizeof(keyPtr));
            
            if ( CFStringGetCString(key, keyPtr, kCCKeySizeAES256, kCFStringEncodingUTF8) ) {
                
                //See the doc: For block ciphers, the output size will always be less than or
                //equal to the input size plus the size of one block.
                //That's why we need to add the size of one block here
                size_t bufferSize = dataLength + kCCBlockSizeAES128;
                void *buffer = malloc(bufferSize);
                const void *cipher = CFDataGetBytePtr(data);
                
                size_t numBytesDecrypted = 0;
                CCCryptorStatus cryptStatus = CCCrypt(
                                                      kCCDecrypt,
                                                      kCCAlgorithmAES128,
                                                      kCCOptionPKCS7Padding,
                                                      keyPtr,
                                                      kCCKeySizeAES256,
                                                      ivptr /* initialization vector (optional) */,
                                                      cipher,
                                                      dataLength, /* input */
                                                      buffer,
                                                      bufferSize, /* output */
                                                      &numBytesDecrypted );
                
                if (cryptStatus == kCCSuccess) {
                    final = CFDataCreate(kCFAllocatorDefault, buffer, numBytesDecrypted);
                }
                
                free(buffer); //free the buffer;
            }
        }
	}
	
	return final;
}
