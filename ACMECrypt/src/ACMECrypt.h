//
//  ACMEAsymCrypt.h
//  ACMECrypt
//
//  Created by Mike De Wolfe on 2013-09-25.
//
//

#ifndef _ACMECRYPT_H_
#define _ACMECRYPT_H_

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonCrypto.h>

#include "ACMEHash.h"
#include "ACMESymmetric.h"

#pragma mark -
#pragma mark DATA TYPES

typedef enum uint32_t {
	kACHMACAlgSHA1   = kCCHmacAlgSHA1,
	kACHMACAlgSHA224 = kCCHmacAlgSHA224,
	kACHMACAlgSHA256 = kCCHmacAlgSHA256,
	kACHMACAlgSHA384 = kCCHmacAlgSHA384,
	kACHMACAlgSHA512 = kCCHmacAlgSHA512,
	kACHMACAlgMD5    = kCCHmacAlgMD5
}ACHMACAlgorithm;

#pragma mark -
#pragma mark FREE STANDING C FUNCTIONS
#pragma mark TO String

/*!
 *	@function
 *		ACMDataToHEX
 *	@abstract
 *		Returns a string containing the uppercase hexits of the provided CFDataRef item.
 *	@param
 *		data (CFDataRef)
 *	@param
 *		upper (bool), pass 'true' if the return value should be in uppercase, 'false' for lowercase.
 *	@return
 *		CFStringRef, 'NULL' if an error occurs.
 */
CFStringRef ACMDataToHEX(CFDataRef data, bool upper);

#pragma mark Randon String Generator

/*!
 *	@function
 *		ACMRandomString
 *	@abstract
 *		Generates a random string of the specified length.
 *	@discussion
 *	@param
 *		length (NSUInteger), desired length of th random string.
 *	@return
 *		CFStringRef, 'NULL' if an error occurs.
 */
CFStringRef ACMRandomString(uint32_t length);

#pragma mark Key Management

/*!
 *	@function
 *		ACGetDefaultPublicKeyX509()
 *	@brief
 *		Returns the key located at the path provided.
 *	@discussion
 *	@param
 *		certPath (NSString*), path to certificate. Certificate must be '.der' encoded.
 *	@return
 *		SecKeyRef, 'NULL' if an error occurs.
 */
SecKeyRef ACMGetPublicKeyX509(CFDataRef certPath);

#pragma mark Assymetric Encryption / Decryption

/*!
 *	@function
 *		ACMEncrypt
 *	@abstract
 *		Encrypts the provided data object with the provided key.
 *	@discussion
 *		The encryption algorithm is supplied by 'publickey.' Uses PKCS1 padding.
 *
 *		If an error occurs, this function will return 'NULL.' If 'data' is 'nil' or has a length of less
 *		1, or 'publickey' is NULL, these cases will be treated as errors.
 *	@param
 *		data (CFDataRef), data to encrypt.
 *	@param
 *		publickey (SecKetRef), encryption key.
 *	@return
 *		CFDataRef, 'NULL' if an error occurs.
 */
CFDataRef ACMEncrypt(CFDataRef data, SecKeyRef publicKey);

/*!
 *	@function
 *		ACMDecrypt
 *	@abstract
 *		Decrypts the provided NSData object using 'key' as the decrytion key.
 *	@discussion
 *		Assumes PKCS! padding.
 *
 *		If 'data' is 'nil,' or 'data.length < 1,' or 'key' is null, these cases will be treated as errors.
 *	@param
 *		data (NSData*), data to decrypt.
 *	@param
 *		key (SecKeyRef), decryption key.
 *	@return
 *		NSData*, decrypted data object, or 'nil' if an error occurs.
 */
CFDataRef ACMDecryptWithKey(CFDataRef data, SecKeyRef key);

#pragma mark Signing

CFDataRef ACMHmac(CFDataRef data, CFStringRef key, ACHMACAlgorithm alg);

#endif
