//
//  ACMEHmacAdditions.h
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-05-04.
//
//

@import Foundation;

#include "ACMEHmac.h"

#pragma mark -
#pragma mark NSString+ACMEHMAC

/**
 *  @name
 *      NSString+ACMEHMAC
 *  @category
 *      NSString+ACMEHMAC
 *  @brief
 *      Convience methods wrapping common HMAC functions, apllied to instances of 'NSString.'
 *
 */
@interface NSString (ACMEHMAC)

#pragma mark Main HMAC Method

/**
 *  @name
 *      Main HMAC Method
 *  @method
 *      acm_hmac:key:encoding:
 *  @brief
 *      Calculates the HMAC of the receiver based on the provided algorithm (alg) and 'key.'
 *  @discussion
 *      This is the main workhorse method, as the other 'NSSTring+ACMEHMAC' methods eventually call
 *      through to this method. An example use case could be:
 *          '[@"string" acm_hmac:kACMHMACAlgMD5 key:@"key" encoding:NSUTF8StringEncoding].'
 *  @param
 *      alg (ACMHMACAlg), HMAC algorithm to use. See 'ACMHMAC.h' for supported algorithms.
 *  @param
 *      key (NSString*), can not be 'nil.'
 *  @param
 *      encoding (NSStringEncoding), encoding the use on the receiver before calculating the HMAC. See
 *      'ACMEHelpMe.h' for supported encodings.
 *  @return
 *      NSString*, HMAC of the receiver as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmac:(ACMHMACAlgorithm)alg key:(NSString*)key encoding:(NSStringEncoding)encoding;

#pragma mark MD5

/**
 *  @name
 *      HMAC-MD5
 *  @method
 *      acm_hmacMD5:
 *  @brief
 *      Calculates the HMAC, using the MD5 algorithm, on the reveiver. the receiver is encoded using
 *      'NSUTF8StringEncoding' before calculating the HMAC.
 *  @param
 *      key (NSString*), can not be 'nil.'
 *  @return
 *      NSString*, HMAC as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacMD5:(NSString*)key;

/**
 *  @name
 *      HMAC-MD5
 *  @method
 *      acm_hmacMD5:encoding:
 *  @brief
 *      Calculates the HMAC (MD5) of the receiver using the provided key. The receiver is encoded with
 *      'encoding' before calculating the hash.
 *  @param
 *      key (NSString*), can not be 'nil.'
 *  @param
 *      encoding (NSStringEncoding), see 'ACMEHelpme.h' for supported string encodings.
 *  @return
 *      NSString*, HMAC as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacMD5:(NSString *)key encoding:(NSStringEncoding)encoding;

#pragma mark SHA

/**
 *  @name
 *      HMAC-SHA
 *  @method
 *      acm_hmacSHA1:
 *  @brief
 *      Calculates the HMAC using the SHA1 algorithm. the receiver is encoded using 'NSUTF8StringEncoding'
 *      before the HMAC is calculated.
 *  @param
 *      key (NSString*), can not be ''nil.'
 *  @return
 *      NSString*, HMAC as lowercase hexits. 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA1:(NSString*)key;

/**
 *  @name
 *      HMAC-SHA
 *  @method
 *      acm_hmacSHA1:encoding:
 *  @brief
 *      Calculates the HMAC (SHA1) of the receiver using the provided key. The receiver is encoded with
 *      'encoding' before calculating the hash.
 *  @param
 *      key (NSString*), can not be 'nil.'
 *  @param
 *      encoding (NSStringEncoding), see 'ACMEHelpme.h' for supported string encodings.
 *  @return
 *      NSString*, HMAC as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA1:(NSString*)key encoding:(NSStringEncoding)encoding;

/**
 *  @name
 *      HMAC-SHA
 *  @method
 *      acm_hmacSHA224:
 *  @brief
 *      Calculates the HMAC using the SHA224 algorithm. the receiver is encoded using 'NSUTF8StringEncoding'
 *      before the HMAC is calculated.
 *  @param
 *      key (NSString*), can not be ''nil.'
 *  @return
 *      NSString*, HMAC as lowercase hexits. 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA224:(NSString*)key;

/**
 *  @name
 *      HMAC-SHA
 *  @method
 *      acm_hmacSHA224:encoding:
 *  @brief
 *      Calculates the HMAC (SHA224) of the receiver using the provided key. The receiver is encoded
 *      with 'encoding' before calculating the hash.
 *  @param
 *      key (NSString*), can not be 'nil.'
 *  @param
 *      encoding (NSStringEncoding), see 'ACMEHelpme.h' for supported string encodings.
 *  @return
 *      NSString*, HMAC as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA224:(NSString*)key encoding:(NSStringEncoding)encoding;

/**
 *  @name
 *      HMAC-SHA
 *  @method
 *      acm_hmacSHA256:
 *  @brief
 *      Calculates the HMAC using the SHA256 algorithm. the receiver is encoded using 'NSUTF8StringEncoding'
 *      before the HMAC is calculated.
 *  @param
 *      key (NSString*), can not be ''nil.'
 *  @return
 *      NSString*, HMAC as lowercase hexits. 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA256:(NSString*)key;

/**
 *  @name
 *      HMAC-SHA
 *  @method
 *      acm_hmacSHA256:encoding:
 *  @brief
 *      Calculates the HMAC (SHA256) of the receiver using the provided key. The receiver is encoded
 *      with 'encoding' before calculating the hash.
 *  @param
 *      key (NSString*), can not be 'nil.'
 *  @param
 *      encoding (NSStringEncoding), see 'ACMEHelpme.h' for supported string encodings.
 *  @return
 *      NSString*, HMAC as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA256:(NSString*)key encoding:(NSStringEncoding)encoding;

/**
 *  @name
 *      HMAC-SHA
 *  @method
 *      acm_hmacSHA384:
 *  @brief
 *      Calculates the HMAC using the SHA384 algorithm. the receiver is encoded using 'NSUTF8StringEncoding'
 *      before the HMAC is calculated.
 *  @param
 *      key (NSString*), can not be ''nil.'
 *  @return
 *      NSString*, HMAC as lowercase hexits. 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA384:(NSString*)key;

/**
 *  @name
 *      HMAC-SHA
 *  @method
 *      acm_hmacSHA384:encoding:
 *  @brief
 *      Calculates the HMAC (SHA384) of the receiver using the provided key. The receiver is encoded
 *      with 'encoding' before calculating the hash.
 *  @param
 *      key (NSString*), can not be 'nil.'
 *  @param
 *      encoding (NSStringEncoding), see 'ACMEHelpme.h' for supported string encodings.
 *  @return
 *      NSString*, HMAC as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA384:(NSString*)key encoding:(NSStringEncoding)encoding;

/**
 *  @name
 *      HMAC-SHA
 *  @method
 *      acm_hmacSHA512:
 *  @brief
 *      Calculates the HMAC using the SHA512 algorithm. the receiver is encoded using 'NSUTF8StringEncoding'
 *      before the HMAC is calculated.
 *  @param
 *      key (NSString*), can not be ''nil.'
 *  @return
 *      NSString*, HMAC as lowercase hexits. 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA512:(NSString*)key;

/**
 *  @name
 *      HMAC-SHA
 *  @method
 *      acm_hmacSHA512:encoding:
 *  @brief
 *      Calculates the HMAC (SHA512) of the receiver using the provided key. The receiver is encoded
 *      with 'encoding' before calculating the hash.
 *  @param
 *      key (NSString*), can not be 'nil.'
 *  @param
 *      encoding (NSStringEncoding), see 'ACMEHelpme.h' for supported string encodings.
 *  @return
 *      NSString*, HMAC as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_hmacSHA512:(NSString*)key encoding:(NSStringEncoding)encoding;

@end

#pragma mark -
#pragma mark NSData+ACMEHMAC

/**
 *	@category
 *		NSData+ACMEHMAC
 *	@brief
 *		Convience methods wrapping common HMAC functions, apllied to instances of 'NSData.'
 */
@interface NSData (ACMEHMAC)

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
