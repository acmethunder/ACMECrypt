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

/**
 *  @category
 *      NSString+ACMEHash
 *  @brief
 *      Convenience methods for common hashing finctions.
 *  @discussion
 *      These methods are convenience wrappers around NSData+ACMEHash.
 */
@interface NSString (ACMEHash)

#pragma mark Main Hashing Method

/**
 *  @name
 *      Main
 *  @method
 *      acm_hash:encoding:
 *  @brief
 *      Encodes the receiver with the providided string encoding, and returns the hash based on the algorithm
 *      provided.
 *  @discussion
 *      This method calls through to '-[NSData(ACMEHash) acm_hash:].'
 *  @param
 *      alg (ACMHashAlg), identifies hashing algorithm.
 *  @param
 *      encoding (NSStringEncoding), validated using `acm_valid_encoding.'
 *  @return
 *      NSString* - Lowercase hexits, 'nil' if validation fails or other erro occurs.
 */
- (NSString*) acm_hash:(ACMHashAlg)alg encoding:(NSStringEncoding)encoding;

#pragma mark Message Digest Methods

/**
 *  @name
 *      Message Digest
 *  @method
 *      acm_md5
 *  @brief
 *      Convenience method for calculating the MD5 hash if the receiver. Calls through to
 *      '-[NSString(ACMEHash) acm_md5HashWithEncoding:]' with 'NSUTF8StringEncoding' encoding.
 *  @return
 *      (NSString*), MD5 of the receiver, 'nil' if an error occurs.
 */
- (NSString*) acm_md5;

/**
 *  @name
 *      Message Digest
 *  @method
 *      acm_md5WithEncoding:
 *  @brief
 *      Encodes the receiver with 'encoding' and returns the MD5 hash.
 *  @discussion
 *      Convenience method which calls through to '-[NSString(ACMEHash) acm_hash:encoding;]' with
 *      'ACMEHashAlgMD5' and 'encoding' as arguments.
 *  @param
 *      encoding (NSStringEncoding), used for encoding the receiver before hashing method is called.
 *  @return
 *      Returns the MD5 hash of the receiver as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*) acm_md5WithEncoding:(NSStringEncoding)encoding;

#pragma mark Secure Hash Algorithm (SHA) Methods

/**
 *  @name
 *      Secure Hash Algorithm (SHA)
 *  @method
 *      acm_sha1
 *  @brief
 *      Convenience wrapper around '-[NSString(ACMEHash) acm_sha1WithEncoding:].' Passes 'NSUTF8StringEncoding'
 *      as the argument.
 *  @return
 *      NSString*, lowercase hexit.
 *  @see
 *      acm_sha1WithEncoding:
 */
- (NSString*)acm_sha1;

/**
 *  @name
 *      Secure Hashing Algorithm (SHA)
 *  @method
 *      acm_sha1WithEncoding:
 *  @brief
 *      Encodes the receiver with 'encoding' and returns the SHA1 hash.
 *  @discussion
 *      Convenience method which calls through to '-[NSString(ACMEHash) acm_hash:encoding;]' with
 *      'ACMEHashAlgSHA1' and 'encoding' as arguments.
 *  @param
 *      encoding (NSStringEncoding), used for encoding the receiver before hashing method is called.
 *  @return
 *      Returns the SHA1 hash of the receiver as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*)acm_sha1WithEncoding:(NSStringEncoding)encoding;

/**
 *  @name
 *      Secure Hash Algorithm (SHA)
 *  @method
 *      acm_sha224
 *  @brief
 *      Convenience wrapper around '-[NSString(ACMEHash) acm_sha224WithEncoding:].' Passes 'NSUTF8StringEncoding'
 *      as the argument.
 *  @return
 *      NSString*, lowercase hexit.
 *  @see
 *      acm_sha224WithEncoding:
 */
- (NSString*)acm_sha224;

/**
 *  @name
 *      Secure Hashing Algorithm (SHA)
 *  @method
 *      acm_sha224WithEncoding:
 *  @brief
 *      Encodes the receiver with 'encoding' and returns the SHA224 hash.
 *  @discussion
 *      Convenience method which calls through to '-[NSString(ACMEHash) acm_hash:encoding;]' with
 *      'ACMEHashAlgSHA224' and 'encoding' as arguments.
 *  @param
 *      encoding (NSStringEncoding), used for encoding the receiver before hashing method is called.
 *  @return
 *      Returns the SHA224 hash of the receiver as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*)acm_sha224WithEncoding:(NSStringEncoding)encoding;

/**
 *  @name
 *      Secure Hash Algorithm (SHA)
 *  @method
 *      acm_sha256
 *  @brief
 *      Convenience wrapper around '-[NSString(ACMEHash) acm_sha256WithEncoding:].' Passes 'NSUTF8StringEncoding'
 *      as the argument.
 *  @return
 *      NSString*, lowercase hexit.
 *  @see
 *      acm_sha256WithEncoding:
 */
- (NSString*)acm_sha256;

/**
 *  @name
 *      Secure Hashing Algorithm (SHA)
 *  @method
 *      acm_sha256WithEncoding:
 *  @brief
 *      Encodes the receiver with 'encoding' and returns the SHA256 hash.
 *  @discussion
 *      Convenience method which calls through to '-[NSString(ACMEHash) acm_hash:encoding;]' with
 *      'ACMEHashAlgSHA256' and 'encoding' as arguments.
 *  @param
 *      encoding (NSStringEncoding), used for encoding the receiver before hashing method is called.
 *  @return
 *      Returns the SHA256 hash of the receiver as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*)acm_sha256WithEncoding:(NSStringEncoding)encoding;

/**
 *  @name
 *      Secure Hash Algorithm (SHA)
 *  @method
 *      acm_sha384
 *  @brief
 *      Convenience wrapper around '-[NSString(ACMEHash) acm_sha384WithEncoding:].' Passes 'NSUTF8StringEncoding'
 *      as the argument.
 *  @return
 *      NSString*, lowercase hexit.
 *  @see
 *      acm_sha384WithEncoding:
 */
- (NSString*)acm_sha384;

/**
 *  @name
 *      Secure Hashing Algorithm (SHA)
 *  @method
 *      acm_sha384WithEncoding:
 *  @brief
 *      Encodes the receiver with 'encoding' and returns the SHA384 hash.
 *  @discussion
 *      Convenience method which calls through to '-[NSString(ACMEHash) acm_hash:encoding;]' with
 *      'ACMEHashAlgSHA384' and 'encoding' as arguments.
 *  @param
 *      encoding (NSStringEncoding), used for encoding the receiver before hashing method is called.
 *  @return
 *      Returns the SHA384 hash of the receiver as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*)acm_sha384WithEncoding:(NSStringEncoding)encoding;

/**
 *  @name
 *      Secure Hash Algorithm (SHA)
 *  @method
 *      acm_sha512
 *  @brief
 *      Convenience wrapper around '-[NSString(ACMEHash) acm_sha512WithEncoding:].' Passes 'NSUTF8StringEncoding'
 *      as the argument.
 *  @return
 *      NSString*, lowercase hexit.
 *  @see
 *      acm_sha512WithEncoding:
 */
- (NSString*)acm_sha512;

/**
 *  @name
 *      Secure Hashing Algorithm (SHA)
 *  @method
 *      acm_sha512WithEncoding:
 *  @brief
 *      Encodes the receiver with 'encoding' and returns the SHA512 hash.
 *  @discussion
 *      Convenience method which calls through to '-[NSString(ACMEHash) acm_hash:encoding;]' with
 *      'ACMEHashAlgSHA512' and 'encoding' as arguments.
 *  @param
 *      encoding (NSStringEncoding), used for encoding the receiver before hashing method is called.
 *  @return
 *      Returns the SHA512 hash of the receiver as lowercase hexits, 'nil' if an error occurs.
 */
- (NSString*)acm_sha512WithEncoding:(NSStringEncoding)encoding;

@end

