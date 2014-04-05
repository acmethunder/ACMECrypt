//
//  ACMEAsymCrypt.m
//  ACMECrypt
//
//  Created by Mike De Wolfe on 2013-09-25.
//
//

#include "ACMECrypt.h"

const char *kACMECryptChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const char *kACryptHEXFormatUpper = "%02X";
const char *kACCryptHEXFormatLower = "%02x";

#pragma mark -
#pragma mark To String

CFStringRef ACMDataToHEX(CFDataRef data, bool upper) {
	CFStringRef final = NULL;
	
	CFIndex dataLength = ( data ? CFDataGetLength(data) : 0 );
	
	if ( dataLength >  0 ) {
		const UInt8 *dataptr = CFDataGetBytePtr(data);
		
		CFMutableStringRef temp = CFStringCreateMutable(kCFAllocatorDefault, dataLength * 2);
		const char *formattype = ( upper ? kACryptHEXFormatUpper : kACCryptHEXFormatLower );
		CFStringRef format = CFStringCreateWithCString(kCFAllocatorDefault, formattype, kCFStringEncodingUTF8);
		
		for ( int i = 0; i < dataLength; ++i ) {
			CFStringAppendFormat(temp, NULL, format, dataptr[i]);
		}
		
		if ( format ) {
			CFRelease(format);
		}
		
		if ( temp ) {
			final = CFStringCreateCopy(kCFAllocatorDefault, temp);
			CFRelease(temp);
		}
	}

	return final;
}

#pragma mark Randon String Generator

CFStringRef ACMRandomString(uint32_t length) {
	CFStringRef final = NULL;
	
	CFMutableStringRef temp = CFStringCreateMutable(kCFAllocatorDefault, (CFIndex)length);
	assert(temp);
    
    int numchars = strlen(kACMECryptChars);
	
	for ( uint32_t i = 0; i < length; ++i ) {
		uint32_t rand = arc4random() % numchars;
		UniChar c = kACMECryptChars[rand];
		CFStringAppendCharacters(temp, &c, 1);
	}
	
	if ( temp ) {
		final = CFStringCreateCopy(kCFAllocatorDefault, temp);
		CFRelease(temp);
	}
	
	return final;
}

#pragma mark Key Management

SecKeyRef ACMGetPublicKeyX509(CFDataRef certData) {
    SecKeyRef keyRef = NULL;
	
	CFIndex length = ( certData ? CFDataGetLength(certData) : (CFIndex)0 );
    
    if ( length > 0 ) {
        SecCertificateRef certRef = SecCertificateCreateWithData(kCFAllocatorDefault, certData);
        SecPolicyRef policy = SecPolicyCreateBasicX509();
        SecTrustRef trust;
        OSStatus status = SecTrustCreateWithCertificates(certRef, policy, &trust);
        
        SecTrustResultType trustResult;
        if ( status == errSecSuccess ) {
            status = SecTrustEvaluate(trust, &trustResult);
            
            if ( status == errSecSuccess ) {
                keyRef = SecTrustCopyPublicKey(trust);
            }
        }
        
        CFRelease(policy);
    }
    
    return keyRef;
}

#pragma mark Symmetric Encryption / Decryption



#pragma mark Assymetric Encryption / Decryption

CFDataRef ACMEncrypt(CFDataRef data, SecKeyRef publicKey) {
    CFDataRef final = 0;
	
	CFIndex dataLength = ( data ? CFDataGetLength(data) : 0 );
    
    if ( (dataLength > 0) || (publicKey) ) {
        size_t max = SecKeyGetBlockSize(publicKey);
        size_t cipherBufferSize = max;
		const uint8_t *fullthing = CFDataGetBytePtr(data);
        const size_t inputBlocSize = cipherBufferSize - 12;
        uint8_t *cipherBuffer = malloc(cipherBufferSize);
		CFMutableDataRef temp = CFDataCreateMutable(kCFAllocatorDefault, cipherBufferSize * dataLength);
		assert(temp);
		
		uint32_t maxlength = dataLength;
        
        for ( size_t block = 0; (block * inputBlocSize) < maxlength; ++block ) {
            size_t blockoffset = block * inputBlocSize;
            const uint8_t *chunk = fullthing + blockoffset;
            const size_t remainingsize = maxlength - blockoffset;
            const size_t subsize = (remainingsize < inputBlocSize ? remainingsize : inputBlocSize);
            
            size_t actualSize = cipherBufferSize;
            
            OSStatus status = SecKeyEncrypt(publicKey, kSecPaddingPKCS1, chunk, subsize, cipherBuffer, &actualSize);
            
            if ( status == errSecSuccess ) {
				CFDataAppendBytes(temp, cipherBuffer, actualSize);
            }
            else {
                printf( "Unable to encrypt data. Status: %ld", status);
				CFRelease(temp);
                temp = NULL;
                break;
            }
        }
        
        if ( temp ) {
			final = CFDataCreateCopy(kCFAllocatorDefault, temp);
			CFRelease(temp);
        }
        
        free(cipherBuffer);
    }
    
    return final;
}

CFDataRef ACMDecryptWithKey(CFDataRef data, SecKeyRef key) {
    CFDataRef final = 0;
	
	CFIndex dataLength = ( data ? CFDataGetLength(data) : 0 );
	
    if ( (dataLength > 0) && key ) {
		size_t max = SecKeyGetBlockSize(key);
        size_t cipherBufferSize = max;
        const uint8_t *fullthing = CFDataGetBytePtr(data);
        const size_t inputBlocSize = cipherBufferSize;
        uint8_t *cipherBuffer = malloc(cipherBufferSize);
        uint32_t maxlength = dataLength;
		CFMutableDataRef temp = CFDataCreateMutable(kCFAllocatorDefault, dataLength);
        
        for ( size_t block = 0; block * inputBlocSize < maxlength; ++block ) {
            size_t blockoffset = block * inputBlocSize;
            const uint8_t *chunk = fullthing + blockoffset;
            const size_t remainingsize = maxlength - blockoffset;
            const size_t subsize = (remainingsize < inputBlocSize ? remainingsize : inputBlocSize);
            
            size_t actualSize = cipherBufferSize;
            
			OSStatus status = SecKeyDecrypt(
											key,
											kSecPaddingPKCS1,
											chunk,
											subsize,
											cipherBuffer,
											&actualSize );
            
            if ( status == errSecSuccess ) {
				CFDataAppendBytes(temp, cipherBuffer, actualSize);
            }
            else {
                printf("Unable to encrypt data. Status: %ld", status);
				CFRelease(temp);
                temp = NULL;
                break;
            }
        }
        
		if ( temp ) {
            final = CFDataCreateCopy(kCFAllocatorDefault, temp);
			CFRelease(temp);
        }
		
        free(cipherBuffer);
    }
    
    return final;
}

#pragma mark Hashing



#pragma mark Signing

CFDataRef ACMHmac(CFDataRef data, CFStringRef key, ACHMACAlgorithm alg) {
	CFIndex dataLength = ( data ? CFDataGetLength(data) : 0 );
	CFIndex keyLength  = ( key ? CFStringGetLength(key) : 0 );
	
	CFDataRef final = NULL;
	
	if ( (dataLength > 0) && (keyLength > 0) ) {
		int digestLength;
		switch (alg) {
			case kACHMACAlgSHA1:
				digestLength = CC_SHA1_DIGEST_LENGTH;
				break;
			case kACHMACAlgSHA224:
				digestLength = CC_SHA224_DIGEST_LENGTH;
				break;
			case kACHMACAlgSHA256:
				digestLength = CC_SHA256_DIGEST_LENGTH;
				break;
			case kACHMACAlgSHA384:
				digestLength = CC_SHA384_DIGEST_LENGTH;
				break;
			case kACHMACAlgSHA512:
				digestLength = CC_SHA512_DIGEST_LENGTH;
				break;
			default:
				digestLength = CC_MD5_DIGEST_LENGTH;
				break;
		}
		
		const char *keyptr = CFStringGetCStringPtr(key, kCFStringEncodingUTF8);
		const char *dataptr = (char*)CFDataGetBytePtr(data);
		unsigned char *chmac = malloc(digestLength);
        memset(chmac, 0, digestLength);
		
		CCHmac(alg, keyptr, keyLength, dataptr, dataLength, chmac);
        final = CFDataCreate(kCFAllocatorDefault, chmac, digestLength);
        
        free(chmac);
	}
	
	return final;
}
