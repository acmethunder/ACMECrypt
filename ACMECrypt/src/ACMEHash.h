//
//  ACMEHash.h
//  ACMECrypt
//
//  Created by Mike De Wolfe on 2014-04-04.
//
//

#ifndef ACMECrypt_ACMEHash_h
#define ACMECrypt_ACMEHash_h

#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonHMAC.h>

CF_EXTERN_C_BEGIN

/**
 *  @enum
 *      ACMHashAlg
 *  @brief
 *      Identifies hashing alforithm
 */
typedef enum {
    ACMHashAlgMD5 = 0,
    ACMHashAlgSHA1,
    ACMHashAlgSHA224,
    ACMHashAlgSHA256,
    ACMHashAlgSHA384,
    ACMHashAlgSHA512
} ACMHashAlg;

/**
 *  @function
 *      acm_hash_valid_algorithm
 *  @brief
 *      Validates that 'alg' is listed in 'ACMEHashAlg.'
 *  @param
 *      alg (ACMHashAlg), algorithm to validate.
 *  @return
 *      'true' if 'alg' is listed in 'ACMEHashAlg,' 'false' otherwise.
 */
bool acm_hash_valid_algorithm(ACMHashAlg alg);

/**
 *  @function
 *      ACMHash
 *  @brief
 *      Calculates the hash of the given data, based on the algorithm provided. Defaults to MD5.
 *  @param
 *      CFDataRef, data object for which to calculate hash.
 *  @param
 *      ACMHashAlg, hashing algorithm.
 *  @return
 *      CFDataRef, NULL if an error occurs.
 */
CFDataRef ACMHash(CFDataRef, ACMHashAlg);

CF_EXTERN_C_END

#endif
