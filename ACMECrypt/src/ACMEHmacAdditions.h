//
//  ACMEHmacAdditions.h
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-05-04.
//
//

@import Foundation;

#include "ACMEHmac.h"

@interface NSString (ACMEHMAC)

- (NSString*)acm_hmac:(ACMHMACAlgorithm)alg key:(NSString*)key encoding:(NSStringEncoding)encoding;

- (NSString*)acm_hmacMD5:(NSString*)key;

- (NSString*) acm_hmacSHA1:(NSString*)key;

@end

@interface NSData (ACMEHMAC)

- (NSString*) acm_hmac:(ACMHMACAlgorithm)alg key:(NSString*)key;

- (NSString*) acm_hmacMD5:(NSString*)key;

- (NSString*) acm_hmacSHA1:(NSString*)key;

- (NSString*) acm_hmacSHA224:(NSString*)key;

- (NSString*) acm_hmacSHA256:(NSString*)key;

- (NSString*) acm_hmacSHA384:(NSString*)key;

- (NSString*) acm_hmacSHA512:(NSString*)key;

@end
