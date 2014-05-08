//
//  NSData+ACMEHmacNSData.h
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-05-07.
//
//

#import <Foundation/Foundation.h>
#import "ACMEHmac.h"

/**
 *	@category
 *		NSData+ACMEHMAC
 *	@brief
 *		Convience methods wrapping common HMAC functions, apllied to instances of 'NSData.'
 */
@interface NSData (ACMEHmacNSData)

#pragma mark -
#pragma mark NSData+ACMEHMAC



#pragma mark Main HMAC Method

/**
 *	@name
 *		Main HMAC Method
 *	@method
 *		acm_hmac:key:
 *	@brief
 *		Calculates the HMAC of the the receiver, using the provided algorithm and key.
 *	@param
 *		alg (ACHMACAlg), hashing algorithm. See 'ACMEHmac.h' for supported algorithms.
 *	@param
 *		key (NSString*), can not be 'nil.'
 *	@return
 *		NSString*, HMAC as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmac:(ACMHMACAlgorithm)alg key:(NSString*)key;

#pragma mark MD5

/**
 *	@name
 *		HMAC+MD5
 *	@method
 *		acm_hmacMD5:
 *	@brief
 *		Calculates the HMAC of the receiver, using the MD5 algorithm, using the provided key.
 *	@param
 *		key (NSString*), can not be 'nil.'
 *	@return
 *		NSString*, as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacMD5:(NSString*)key;

#pragma mark SHA

/**
 *	@name
 *		HMAC+SHA
 *	@method
 *		acm_hmacSHA1:
 *	@brief
 *		Calculates the HMAC of the receiver, using the SHA1 algorithm, using the provided key.
 *	@param
 *		key (NSString*), can not be 'nil.'
 *	@return
 *		NSString*, as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA1:(NSString*)key;

/**
 *	@name
 *		HMAC+SHA
 *	@method
 *		acm_hmacSHA224:
 *	@brief
 *		Calculates the HMAC of the receiver, using the SHA224 algorithm, using the provided key.
 *	@param
 *		key (NSString*), can not be 'nil.'
 *	@return
 *		NSString*, as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA224:(NSString*)key;

/**
 *	@name
 *		HMAC+SHA
 *	@method
 *		acm_hmacSHA256:
 *	@brief
 *		Calculates the HMAC of the receiver, using the SHA256 algorithm, using the provided key.
 *	@param
 *		key (NSString*), can not be 'nil.'
 *	@return
 *		NSString*, as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA256:(NSString*)key;

/**
 *	@name
 *		HMAC+SHA
 *	@method
 *		acm_hmacSHA384:
 *	@brief
 *		Calculates the HMAC of the receiver, using the SHA384 algorithm, using the provided key.
 *	@param
 *		key (NSString*), can not be 'nil.'
 *	@return
 *		NSString*, as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA384:(NSString*)key;

/**
 *	@name
 *		HMAC+SHA
 *	@method
 *		acm_hmacSHA512:
 *	@brief
 *		Calculates the HMAC of the receiver, using the SHA512 algorithm, using the provided key.
 *	@param
 *		key (NSString*), can not be 'nil.'
 *	@return
 *		NSString*, as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA512:(NSString*)key;

@end
