//
//  ACMEAsymCrypt.h
//  ACMECrypt
//
//  Created by Mike De Wolfe on 2013-09-25.
//
//

#import <Foundation/Foundation.h>

#pragma mark -
#pragma mark FREE STANDING C FUNCTIONS
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
 *		data (NSData*), data to encrypt.
 *	@param
 *		key (NSString*), encryption key.
 *	@param
 *		initVector (NSString*)
 *	@return
 *		NSData*, 'nil' if an error occurs.
 */
CFDataRef ACEncryptAES256(CFDataRef data, CFStringRef key, CFStringRef initVector );

/*!
 *	@function
 *		ACDecryptAES256
 *	@abstract
 *		Decrypts the provided binary object.
 *	@discussion
 *		If 'data,' 'key,' or 'initVector,' have a length of less than 1, this will be considered an error.
 *	@param
 *		data (NSData*), data to decrypt.
 *	@param
 *		key (NSString*), decryption key.
 *	@param
 *		initVector (NSString*), intialization vector.
 *	@return
 *		NSData*, decrypted data, 'nil' if an error occurs.
 */
NSData* ACDecryptAES256(NSData *data, NSString *key, NSString *initVector );

#pragma mark Assymetric Encryption / Decryption

/*!
 *	@function
 *		ECEncrypt
 *	@abstract
 *		Encrypts the provided data object with the provided key.
 *	@discussion
 *		The encryption algorithm is supplied by 'publickey.' Uses PKCS1 padding.
 *
 *		If an error occurs, this function will return 'nil.' If 'data' is 'nil' or has a length of less
 *		1, or 'publickey' is NULL, these cases will be treated as errors.
 *	@param
 *		data (NSData*), data to encrypt.
 *	@param
 *		publickey (SecKetRef), encryption key.
 *	@return
 *		NSData*, 'nil' if an error occurs.
 */
NSData* ACEncrypt(NSData *data, SecKeyRef publicKey);

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
NSData* ACDecryptWithKey(NSData* data, SecKeyRef key);

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
 *		CFStringRef, MD5 as lowercase hex values., 'NULL' if an error occurs.
 */
CFStringRef ACGetMD5(CFDataRef data);

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
 * randomStringGenerator:
 * @abstract
 * Generates a andom string of the desirted length.
 * @param
 * int length - Length of the desired random string.
 * @return
 * NSString - Randomly generated string. Auto released.
 */
+(NSString *)randomStringGenerator:(int)length;

/*!
 * @method
 * encryptSTring:withKey:andVector
 * @abstract
 * Returns and NSData object representing the plaint tex string passed in.
 * @discussion
 * Encrypts the plain text string with AES256 encryption. Returns the encrypted string as an NSData
 * object.
 * @param
 * NSString *plainText - string to encrypt.
 * @param
 * NSString *key - encryption key.
 * @param
 * NSstring *initVector -
 * @return
 * NSData - encrypted data object representing "plainText." Autoreleased.
 */
+(NSData *)encryptString:(NSString *)plaintext withKey:(NSString *)key andVector:(NSString *)initVector;

/*!
 * @method
 * decryptData:withKey:andVector;
 * @abstract
 * Decrypts the provided NSData object, and returns a the plain text string.
 * @discussion
 * @param
 * NSData *cipherText - Data object to be decrypted.
 * @param
 * NSString *key - decryption key.
 * @param
 * NSString *initViector -
 * @return
 * NSString - decrypted plain text string. Autoreleased.
 */
+(NSString *)decryptData:(NSData *)ciphertext withKey:(NSString *)key andVector:(NSString *)initVector;


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
