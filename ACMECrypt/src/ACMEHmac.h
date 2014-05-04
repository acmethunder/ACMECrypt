//
//  ACMEHmac.h
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-05-04.
//
//

#ifndef ACMECrypt_ACMEHmac_h
#define ACMECrypt_ACMEHmac_h

#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonCrypto.h>

CF_EXTERN_C_BEGIN

#pragma mark -
#pragma mark Data Types

/**
 *  @enum
 *      ACMHMACAlg
 *  @brief
 *      Supported HMAC algorithms.
 */
typedef enum uint32_t {
	kACMHMACAlgSHA1   = kCCHmacAlgSHA1,
	kACMHMACAlgSHA224 = kCCHmacAlgSHA224,
	kACMHMACAlgSHA256 = kCCHmacAlgSHA256,
	kACMHMACAlgSHA384 = kCCHmacAlgSHA384,
	kACMHMACAlgSHA512 = kCCHmacAlgSHA512,
	kACMHMACAlgMD5    = kCCHmacAlgMD5
}ACMHMACAlgorithm;

#pragma mark Validation

/**
 *  @name
 *      Validation
 *  @function
 *      acm_valid_hmac_alg
 *  @param
 *      alg (ACMHAMCAlg)
 *  @return
 *      'true' if 'alg' is equal to any of the supported HMAC algorithms, 'false' otherwise.
 */
bool acm_valid_hmac_alg(ACMHMACAlgorithm alg);

#pragma mark Hash Based Message Authentication Code (HMAC)

/**
 *  @name
 *      Hash Based Message Authentication Code (HMAC)
 *  @function
 *      ACMHmac
 *  @brief
 *      Calculates the HMAC of the prodided data object based on the provided algorithm.
 *  @param
 *      data (CFDataRef)
 */
CFDataRef ACMHmac(CFDataRef data, CFStringRef key, ACMHMACAlgorithm alg);

CF_EXTERN_C_END

#endif
