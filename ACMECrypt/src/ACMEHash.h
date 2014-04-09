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
 *	@function
 *		ECGetMD5
 *	@abstract
 *		Calculates the MD5 hash of the provided data object.
 *	@discussion
 *		Will only calculate the MD5 hash if the provided data object has a lenght of greater than zero.
 *	@param
 *		data (CFDataRef), data to hash.
 *	@return
 *		CFDataRef, 'NULL' if an error occurs.
 */
//CFDataRef ACGetMD5(CFDataRef data);
//
//CFDataRef ACGetSHA1(CFDataRef data);
//
//CFDataRef ACGetSHA224(CFDataRef data);
//
//CFDataRef ACGetSHA256(CFDataRef data);
//
//CFDataRef ACGetSHA384(CFDataRef data);
//
//CFDataRef ACGetSHA512(CFDataRef data);

/**
 *  @function
 *      ACMHash
 *  @brief
 *      Calculates the hash of the given data, based on the algorithm provided. Defaults to MD5.
 *  @param
 *      CFDataRef, data object for which to calculate hash.
 *  @param
 *      ACMHashAlg, hashng algorithm.
 *  @return
 *      CFDataRef, NULL if an error occurs.
 */
CFDataRef ACMHash(CFDataRef, ACMHashAlg);

#endif
