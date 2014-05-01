//
//  ACMEHelpers.h
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-04-29.
//
//

@import Foundation;

#include "ACMEHash.h"

#pragma mark -
#pragma mark NSString+ACMEHash

@interface NSString (ACMEHash)

#pragma mark MD5

/**
 *  @method
 *      acm_md5
 *  @brief
 *      Convenience method for calculating the MD5 hash if the receiver. Calls through to
 *      '-[NSString(ACMEHash) acm_md5HashWithEncoding:]' with 'NSUTF8StringEncoding' as the paramter.
 *  @return
 *      (NSString*), MD5 of the receiver, 'nil' if an error occurs.
 */
-(NSString*) acm_md5Hash;

/**
 *  @method
 *      acm_md5WithEncoding:
 *  @brief
 *      Encodes the receover with 'encoding' and returns the MD5 hash.
 *  @param
 *      encoding (NSStringEncoding)
 *  @return
 *      Returns the MD5 hash of the receiver, 'nil' if an error occurs.
 */
-(NSString*) acm_md5HashWithEncoding:(NSStringEncoding)encoding;

@end

#pragma mark -
#pragma mark NSData+ACMEHash

/**
 *  @category
 *      NSData+ACMEHash
 *  @brief
 *      Common hashing functions applied to NSData
 */
@interface NSData (ACMEHash)

/**
 *  @method
 *      acm_hash:
 *  @brief
 *      Calaculates hash of the receiver using the provided algorithm.
 *  @param
 *      alg (ACMHashAlg), identifies hashing algorithm to use. See 'ACMEHash.h' for accepted algorithms.
 *  @return
 *      NSString*, lowercase, 'nil' if an error occurs, or the value of 'alg falss outside the accepted
 *      values.
 *  @see
 *      ACMEHash.h
 */
-(NSString*)acm_hash:(ACMHashAlg)alg;

/**
 *  @discussion
 *      The following methods are simply convenience methods, which call through to '-[NSData(ACMEHash) acm_hash:]'
 *      with the appropriate algorithm.
 */

/** @method acm_md5 */
-(NSString*) acm_md5Hash;

/** @method acm_sha1 */
-(NSString*)acm_sha1;

/** @method acm_sha224 */
-(NSString*)acm_sha224;

/** @method acm_sha256 */
-(NSString*)acm_sha256;

/** @method acm_sha384 */
-(NSString*)acm_sha384;

/** @method acm_sha512 */
-(NSString*)acm_sha512;

@end
