//
//  ACMEHmac.c
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-05-04.
//
//

#include "ACMEHmac.h"

#pragma mark Validation

bool acm_valid_hmac_alg(ACMHMACAlgorithm alg) {
    bool is_good;
    
    switch ( alg ) {
        case kACMHMACAlgMD5 :
        case kACMHMACAlgSHA1 :
        case kACMHMACAlgSHA224 :
        case kACMHMACAlgSHA256 :
        case kACMHMACAlgSHA384 :
        case kACMHMACAlgSHA512 : is_good = true;
            break;
        default : is_good = false;
            break;
    }
    
    return is_good;
}

#pragma mark Signing

CFDataRef ACMHmac(CFDataRef data, CFStringRef key, ACMHMACAlgorithm alg) {
	CFIndex dataLength = ( data ? CFDataGetLength(data) : 0 );
	CFIndex keyLength  = ( key ? CFStringGetLength(key) : 0 );
	
	CFDataRef final = NULL;
	
	if ( (dataLength > 0) && (keyLength > 0) ) {
		int digestLength;
		switch (alg) {
			case kACMHMACAlgSHA1:
				digestLength = CC_SHA1_DIGEST_LENGTH;
				break;
			case kACMHMACAlgSHA224:
				digestLength = CC_SHA224_DIGEST_LENGTH;
				break;
			case kACMHMACAlgSHA256:
				digestLength = CC_SHA256_DIGEST_LENGTH;
				break;
			case kACMHMACAlgSHA384:
				digestLength = CC_SHA384_DIGEST_LENGTH;
				break;
			case kACMHMACAlgSHA512:
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
