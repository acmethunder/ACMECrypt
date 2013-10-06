//
//  ACMEAsymCrypt.h
//  ACMECrypt
//
//  Created by Mike De Wolfe on 2013-09-25.
//
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonHMAC.h>

#pragma mark -
#pragma mark DATA TYPES

typedef enum uint32_t {
	kACHMACAlgSHA1 = kCCHmacAlgSHA1,
	kACHMACAlgSHA224 = kCCHmacAlgSHA224,
	kACHMACAlgSHA256 = kCCHmacAlgSHA256,
	kACHMACAlgSHA384 = kCCHmacAlgSHA384,
	kACHMACAlgSHA512 = kCCHmacAlgSHA512,
	kACHMACAlgMD5 = kCCHmacAlgMD5
}ACHAMCAlgorithm;

#pragma mark -
#pragma mark FREE STANDING C FUNCTIONS
#pragma mark TO String

/*!
 *	@function
 *		ACDataToHEX
 *	@abstract
 *		Returns a string containing the uppercase hexits of the provided CFDataRef item.
 *	@param
 *		data (CFDataRef)
 *	@return
 *		CFStringRef, 'NULL' if an error occurs.
 */
CFStringRef ACDataToHEX(CFDataRef data);

#pragma mark Randon String Generator

/*!
 *	@function
 *		ACRandomString
 *	@abstract
 *		Generates a random string of the specified length.
 *	@discussion
 *	@param
 *		length (NSUInteger), desired length of th random string.
 *	@return
 *		CFStringRef, 'NULL' if an error occurs.
 */
CFStringRef ACRandomString(NSUInteger length);

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
SecKeyRef ACGetPublicKeyX509(CFStringRef certPath);

#pragma mark Symmetric Encryption / Decryption

/*!
 *	@function
 *		ECEncryptAES256
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
CFDataRef ACEncryptAES256(CFDataRef data, CFStringRef key, CFStringRef initVector);

/*!
 *	@function
 *		ACDecryptAES256
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
CFDataRef ACDecryptAES256(CFDataRef data, CFStringRef key, CFStringRef initVector);

#pragma mark Assymetric Encryption / Decryption

/*!
 *	@function
 *		ACEncrypt
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
CFDataRef ACEncrypt(CFDataRef data, SecKeyRef publicKey);

/*!
 *	@function
 *		ECDecrypt
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
CFDataRef ACDecryptWithKey(CFDataRef data, SecKeyRef key);

#pragma mark Hashing

/*!
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
CFDataRef ACGetMD5(CFDataRef data);

#pragma mark Signing

CFDataRef ACHmac(CFDataRef data, CFStringRef key, ACHAMCAlgorithm alg);

#pragma mark -
#pragma mark EncryptionController DECLARATION

/*!
 * @class
 * EncryptionController
 * @abstract
 * @discussion
 */
@interface ACMECrypt : NSObject


/*!
 * @method
 * HMACSHA256:withKey:
 * @abstract
 * Returns a hash of the provided string.
 * @discussion
 * The returned string is hex repsentation of the encrypted string.
 * @param
 * string, NSString to encrypt.
 * @param
 * key, Encryption key
 * @return
 * Encrypted string, 'nil' if an error occurs.
 */
+(NSString *)HMACSHA256String:(NSString *)string withKey:(NSString *)key;

/*!
 * @method
 * HMACMD5:withKey:
 * @abstract
 * Hashes the provided NSData object with the provided key, using the MD5 algorithm.
 * @discussion
 * Possible errors that will cause this method to return 'nil':
 * - 'key' is 'nil' or an empty string.
 * - 'data' is not actually an instance of NSData.
 * @param
 * data (NSData*), item to hash.
 * @param
 * key (NSString*), key used by hashing algorithm.
 * @return
 * NSString* - MD% hash of the provided data object, 'nil' if an error occurs.
 */
+(NSString*)HMACMD5:(NSData*)data withKey:(NSString*)key;

@end
