//
//  ACMESymmetric.h
//  ACMECrypt
//
//  Created by Mike De Wolfe on 2014-04-04.
//
//

#ifndef ACMECrypt_ACMESymmetric_h
#define ACMECrypt_ACMESymmetric_h

#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonCrypto.h>

//typedef enum {
//    ACM
//}ACMSymmCryptAlg;


typedef struct {
    CCAlgorithm alg;
    CCOptions options;
}ACMCryptInfo;

/*!
 *	@function
 *		ACMEncryptAES256
 *	@abstract
 *		Encrypts the provided NSData object with key and initialization vector.
 *	@discussion
 *		Any of the following cases will be considered an error (in addition to the ecryption itself failing):
 *			- data.length < 1
 *			- key is emtpy ot 'nil.'
 *			- initVector is empty or 'nil.'
 *	@param
 *		data (CFDataRef), data to encrypt.
 *	@param
 *		key (CFStringRef), encryption key.
 *	@param
 *		initVector (CFStringRef)
 *	@return
 *		CFDataRef, 'NULL' if an error occurs.
 */
CFDataRef ACMEncryptAES256(CFDataRef data, CFStringRef key, CFStringRef initVector);

/*!
 *	@function
 *		ACMDecryptAES256
 *	@abstract
 *		Decrypts the provided binary object.
 *	@discussion
 *		If 'data,' 'key,' or 'initVector,' have a length of less than 1, this will be considered an error.
 *	@param
 *		data (CFDataRef), data to decrypt.
 *	@param
 *		key (CFStringRef), decryption key.
 *	@param
 *		initVector (CFStringRef), intialization vector.
 *	@return
 *		CFDataRef, decrypted data, 'NULL' if an error occurs.
 */
CFDataRef ACMDecryptAES256(CFDataRef data, CFStringRef key, CFStringRef initVector);

CFDataRef ACMSymmCrypt(CFDataRef data,CFStringRef key, CFStringRef initVector, ACMCryptInfo info);

inline ACMCryptInfo ACMCryptInfoMake( CCAlgorithm alg, CCOptions options);



#endif
