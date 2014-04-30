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

#endif
