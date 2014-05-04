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

@interface NSString (ACMEHMAC)

#pragma mark Main HMAC Method

- (NSString*) acm_hmac:(ACMHMACAlgorithm)alg key:(NSString*)key encoding:(NSStringEncoding)encoding;

#pragma mark MD5

- (NSString*) acm_hmacMD5:(NSString*)key;
- (NSString*) acm_hmacMD5:(NSString *)key encoding:(NSStringEncoding)encoding;

#pragma mark SHA

- (NSString*) acm_hmacSHA1:(NSString*)key;
- (NSString*) acm_hmacSHA1:(NSString *)key encoding:(NSStringEncoding)encoding;

- (NSString*) acm_hmacSHA224:(NSString*)key;
- (NSString*) acm_hmacSHA224:(NSString*)key encoding:(NSStringEncoding)encoding;

- (NSString*) acm_hmacSHA256:(NSString*)key;
- (NSString*) acm_hmacSHA256:(NSString *)key encoding:(NSStringEncoding)encoding;

- (NSString*) acm_hmacSHA384:(NSString*)key;
- (NSString*) acm_hmacSHA384:(NSString *)key encoding:(NSStringEncoding)encoding;

- (NSString*) acm_hmacSHA512:(NSString*)key;
- (NSString*) acm_hmacSHA512:(NSString *)key encoding:(NSStringEncoding)encoding;

@end

#pragma mark -
#pragma mark NSData+ACMEHMAC

@interface NSData (ACMEHMAC)

#pragma mark Main HMAC Method

- (NSString*) acm_hmac:(ACMHMACAlgorithm)alg key:(NSString*)key;

#pragma mark MD5

- (NSString*) acm_hmacMD5:(NSString*)key;

#pragma mark SHA

- (NSString*) acm_hmacSHA1:(NSString*)key;

- (NSString*) acm_hmacSHA224:(NSString*)key;

- (NSString*) acm_hmacSHA256:(NSString*)key;

- (NSString*) acm_hmacSHA384:(NSString*)key;

- (NSString*) acm_hmacSHA512:(NSString*)key;

@end
