//
//  ACMEHelpers.h
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-04-29.
//
//

@import Foundation;

#pragma mark -
#pragma mark NSString+ACMEHash

@interface NSString (ACMEHash)

- (NSString*) acm_md5Hash;

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
 *      acm_md5
 *  @brief
 *      Calculates and returns the MD5 hash of the receiver.
 *  @return
 *      (NSString*) MD5 hash of the receiver, 'nil' if an error occurs.
 */
- (NSString*) acm_md5Hash;

@end
