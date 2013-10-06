//
//  ACMEAsymCrypt.m
//  ACMECrypt
//
//  Created by Mike De Wolfe on 2013-09-25.
//
//

#import <CommonCrypto/CommonCrypto.h>
#import "ACMECrypt.h"

const char *kACMECryptChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const char *kACryptHEXFormat = "%02X";

const int kACMECryprNumChars = 62;

#pragma mark -
#pragma mark FREE STANDING C FUNCTIONS
#pragma mark TO String

CFStringRef ACDataToHEX(CFDataRef data) {
	CFStringRef final = NULL;
	
	CFIndex dataLength = ( data ? CFDataGetLength(data) : 0 );
	
	if ( dataLength >  0 ) {
		const UInt8 *dataptr = CFDataGetBytePtr(data);
		
		CFMutableStringRef temp = CFStringCreateMutable(kCFAllocatorDefault, dataLength * 2);
		CFStringRef format = CFStringCreateWithCString(kCFAllocatorDefault, kACryptHEXFormat, kCFStringEncodingUTF8);
		
		for ( int i = 0; i < dataLength; ++i ) {
			CFStringAppendFormat(temp, NULL, format, dataptr[i]);
		}
		
		if ( CFStringGetLength(temp) > 0 ) {
			final = CFStringCreateCopy(kCFAllocatorDefault, temp);
		}
	}
	
	
	return final;
}

#pragma mark Randon String Generator

CFStringRef ACRandomString(NSUInteger length) {
	CFStringRef final = NULL;
	
	CFMutableStringRef temp = CFStringCreateMutable(kCFAllocatorDefault, (CFIndex)length);
	
	for ( NSUInteger i = 0; i < length; ++i ) {
		NSUInteger rand = arc4random() % kACMECryprNumChars;
		UniChar c = kACMECryptChars[rand];
		CFStringAppendCharacters(temp, &c, 1);
	}
	
	if ( CFStringGetLength(temp) > 0 ) {
		final = CFStringCreateCopy(kCFAllocatorDefault, temp);
	}
	
	return final;
}

#pragma mark Key Management

SecKeyRef ACGetPublicKeyX509(CFStringRef certPath) {
    SecKeyRef keyRef = NULL;
	
	CFIndex length = ( certPath ? CFStringGetLength(certPath) : (CFIndex)0 );
	
	if ( length < 1 ) {
		return NULL;
	}
    
    NSData *certData = [[NSData alloc] initWithContentsOfFile:(__bridge NSString *)(certPath)];
    if ( certData.length > 0 ) {
        SecCertificateRef certRef = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certData);
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

CFDataRef ACEncryptAES256(CFDataRef data, CFStringRef key, CFStringRef initVector) {
    CFDataRef final = NULL;
	
	CFIndex dataLength = ( data ? CFDataGetLength(data) : (CFIndex)0 );
	CFIndex keyLength  = ( key ? CFStringGetLength(key) : (CFIndex)0 );
	CFIndex ivLength   = ( initVector ? CFStringGetLength(initVector) : (CFIndex)0 );
    
    if ( (dataLength > 0) && (keyLength > 0) && (ivLength > 0) ) {
		const char *ivptr = CFStringGetCStringPtr(initVector, kCFStringEncodingUTF8);

		if ( ! ivptr ) {
			return NULL;
		}
		
        char keyptr[kCCKeySizeAES256 + 1];
        memset(keyptr, 0, sizeof(keyptr));
        
		if ( ! CFStringGetCString(key, keyptr, kCCKeySizeAES256 + 1, kCFStringEncodingUTF8) ) {
			return NULL;
		}
        
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
    
    
    return final;
}

CFDataRef ACDecryptAES256(CFDataRef data, CFStringRef key, CFStringRef initVector) {
	CFDataRef final = 0;
	
	CFIndex dataLength = ( data ? CFDataGetLength(data) : 0 );
	CFIndex keyLength  = ( key ? CFStringGetLength(key) : 0 );
	CFIndex ivLength   = ( initVector ? CFStringGetLength(initVector) : 0 );
	
	if ( (dataLength > 0) && (keyLength > 0) && (ivLength > 0) ) {
		const char *ivptr = CFStringGetCStringPtr(initVector, kCFStringEncodingUTF8);
		
		if ( ! ivptr ) {
			return NULL;
		}
		
		char keyPtr[kCCKeySizeAES256+1];	// 'key' should be 32 bytes for AES256, will be null-padded otherwise
		memset(keyPtr, 0, sizeof(keyPtr));
		
		if ( ! CFStringGetCString(key, keyPtr, kCCKeySizeAES256+1, kCFStringEncodingUTF8) ) {
			return NULL;
		}
		
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
	
	return final;
}

#pragma mark Assymetric Encryption / Decryption

CFDataRef ACEncrypt(CFDataRef data, SecKeyRef publicKey) {
    CFDataRef final = 0;
	
	CFIndex dataLength = ( data ? CFDataGetLength(data) : (CFIndex)0 );
    
    if ( (dataLength > 0) || (publicKey) ) {
        size_t max = SecKeyGetBlockSize(publicKey);
        size_t cipherBufferSize = max;
		const uint8_t *fullthing = CFDataGetBytePtr(data);
        const size_t inputBlocSize = cipherBufferSize - 12;
        uint8_t *cipherBuffer = malloc(cipherBufferSize);
		CFMutableDataRef temp = CFDataCreateMutable(kCFAllocatorDefault, cipherBufferSize * dataLength);
		NSUInteger maxlength = dataLength;
        
        for ( size_t block = 0; block * inputBlocSize < maxlength; ++block ) {
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
                NSLog( @"Unable to encrypt data. Status: %ld", status);
                temp = 0;
                break;
            }
        }
        
        if ( temp && (CFDataGetLength(temp) > 0) ) {
			final = CFDataCreateCopy(kCFAllocatorDefault, temp);
        }
        
        free(cipherBuffer);
    }
    
    return final;
}

CFDataRef ACDecryptWithKey(CFDataRef data, SecKeyRef key) {
    CFDataRef final = 0;
	
	CFIndex dataLength = ( data ? CFDataGetLength(data) : 0 );
	
    if ( (dataLength > 0) && key ) {
		size_t max = SecKeyGetBlockSize(key);
        size_t cipherBufferSize = max;
        const uint8_t *fullthing = CFDataGetBytePtr(data);
        const size_t inputBlocSize = cipherBufferSize;
        uint8_t *cipherBuffer = malloc(cipherBufferSize);
        NSUInteger maxlength = dataLength;
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
                NSLog( @"Unable to encrypt data. Status: %ld", status);
                temp = 0;
                break;
            }
        }
        
		if ( temp && (CFDataGetLength(temp) > 0) ) {
            final = CFDataCreateCopy(kCFAllocatorDefault, temp);
        }
        
        free(cipherBuffer);
    }
    
    return final;
}

#pragma mark Hashing

CFDataRef ACGetMD5(CFDataRef data) {
	CFDataRef final = NULL;
    CFIndex length = ( data ? CFDataGetLength(data) : 0 );
    if ( length > 0 ) {
        const char *plainText = (char*)CFDataGetBytePtr(data);
        unsigned char digest[CC_MD5_DIGEST_LENGTH];
        
        CC_MD5(plainText, length, digest);
		
		final = CFDataCreate(kCFAllocatorDefault, digest, CC_MD5_DIGEST_LENGTH);
    }
    
    return final;
}

#pragma mark Signing

CFDataRef ACHmac(CFDataRef data, CFStringRef key, ACHAMCAlgorithm alg) {
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
		
		unsigned char chmac[digestLength];
		
		CCHmac(alg, keyptr, keyLength, dataptr, dataLength, chmac);
		
		final = CFDataCreate(kCFAllocatorDefault, chmac, sizeof(chmac));
	}
	
	return final;
}

#pragma mark -
#pragma mark ACMEAssymCrypt IMPLEMENTATION


@implementation ACMECrypt

+(NSString *)HMACSHA256String:(NSString *)string withKey:(NSString *)key {
    NSString *new = 0;
    NSString *hash = 0;
    NSData *hmac = 0;
    NSMutableString *temp = [[NSMutableString alloc] initWithString:@""];
    
    if ( ! key ) {
        NSLog( @"Can not hash, no key provided" );
        return 0;
    }
    
    if ( [string isKindOfClass:[NSString class]] ) {
        new = string;
    }
    else {
        new = @"";
    }
    
    const char *cKey = [key cStringUsingEncoding:NSASCIIStringEncoding];
    const char *cData = [new cStringUsingEncoding:NSASCIIStringEncoding];
    
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    unsigned char *digest;
    unsigned int dLength;
    
    CCHmac( kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC );
    
    hmac = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    
    digest = (unsigned char *)[hmac bytes];
    dLength = hmac.length;
    
    for ( int i = 0; i < dLength; ++i ) {
        [temp appendFormat:@"%02X", digest[i]];
    }
    
    hash = [[NSString alloc] initWithString:temp];
    
    return hash;
}

+(NSString*)HMACMD5:(NSData*)data withKey:(NSString*)key {
    NSString *md5Hash = 0;
    NSAssert( key.length > 0, @"" );
    
    if ( [data isKindOfClass:[NSData class]] && (key.length > 0) ) {
        unsigned char cHMAC[CC_MD5_DIGEST_LENGTH];
        unsigned char *digest;
        NSUInteger dLength;
        
        const char *cKey = [key cStringUsingEncoding:NSASCIIStringEncoding];
        
        CCHmac( kCCHmacAlgMD5, cKey, strlen(cKey), [data bytes], data.length, cHMAC );
        
        NSData *hmac = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
        
        digest = (unsigned char *)[hmac bytes];
        dLength = hmac.length;
        
        NSMutableString *temp = [[NSMutableString alloc] init];
        
        for ( NSUInteger i = 0; i < dLength; ++i ) {
            [temp appendFormat:@"%02X", digest[i]];
        }
        
        md5Hash = [[NSString alloc] initWithString:temp];
    }
    
    return md5Hash;
}

//+(NSData*)RSAEncrypt:(NSData*)data withKey:(SecKeyRef)publicKey {
// NSData *final = 0;
//
// if ( (data.length > 0) || (publicKey) ) {
// size_t max = SecKeyGetBlockSize(publicKey) - 11;
//
// if ( data.length > max ) {
// NSLog( @"Content (%ld) too long must be < '%ld.'", (unsigned long)data.length, max );
// return 0;
// }
//
//
//
//
// size_t plainBufferSize = (size_t)data.length;
// size_t cipherBufferSize = max;
//
// uint8_t *cipherBuffer = malloc(cipherBufferSize);
// uint8_t *plainBuffer = (uint8_t*)[data bytes];
//
// OSStatus status = SecKeyEncrypt(
// publicKey,
// kSecPaddingPKCS1,
// plainBuffer,
// plainBufferSize,
// cipherBuffer,
// &cipherBufferSize);
//
// if ( status == errSecSuccess ) {
// final = [[NSData alloc] initWithBytes:cipherBuffer length:cipherBufferSize];
// }
//
// free( cipherBuffer );
//
//
// }
//
// return final;
//}

@end
