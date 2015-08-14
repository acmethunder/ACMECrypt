//
//  NSData+ACMEHash.h
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-05-07.
//
//

#import <Foundation/Foundation.h>
#include "ACMEHash.h"

#pragma mark -
#pragma mark NSData+ACMEHash

/**
 *  @category
 *      NSData+ACMEHash
 *  @brief
 *      Common hashing functions applied to NSData
 */
@interface NSData (ACMEHash)

- (NSData*) acm_hashRaw:(ACMHashAlg)alg;

/**
 *  @method
 *      acm_hash:
 *  @brief
 *      Calaculates hash of the receiver using the provided algorithm.
 *  @param
 *      alg (ACMHashAlg), identifies hashing algorithm to use. See 'ACMEHash.h' for list ofaccepted
 *      algorithms.
 *  @return
 *      NSString*, lowercase, 'nil' if an error occurs, or the value of 'alg falls outside the accepted
 *      values.
 *  @see
 *      ACMEHash.h
 */
- (NSString*)acm_hash:(ACMHashAlg)alg;

/**
 *  @discussion
 *      The following methods are simply convenience methods, which call through to '-[NSData(ACMEHash) acm_hash:]'
 *      with the appropriate algorithm.
 */

#pragma mark Message Digest Methods

/** @method acm_md5 */
- (NSString*) acm_md5;

#pragma mark Secure Hashing Algorithm (SHA) Methods

/** @method acm_sha1 */
- (NSString*)acm_sha1;

/** @method acm_sha224 */
- (NSString*)acm_sha224;

/** @method acm_sha256 */
- (NSString*)acm_sha256;

/** @method acm_sha384 */
- (NSString*)acm_sha384;

/** @method acm_sha512 */
- (NSString*)acm_sha512;

@end

