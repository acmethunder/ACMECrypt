//
//  ACMEHmacAdditions.m
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-05-04.
//
//

#import "NSString+ACMEHmac.h"
#import "ACMEHelpMe.h"
#import "ACMEStrings.h"
#import "NSData+ACMEHmac.h"

@implementation NSString (ACMEHMAC)

- (NSString*) acm_hmac:(ACMHMACAlgorithm)alg key:(NSString *)key encoding:(NSStringEncoding)encoding {
    NSString *final = nil;
    
    if ( acm_valid_encoding(encoding) ) {
        NSData *data = [self dataUsingEncoding:encoding];
        final = [data acm_hmac:alg key:key];
    }

    return final;
}

- (NSString*)acm_hmacMD5:(NSString*)key {
    return [self acm_hmacMD5:key encoding:NSUTF8StringEncoding];
}

- (NSString*) acm_hmacMD5:(NSString *)key encoding:(NSStringEncoding)encoding {
    return [self acm_hmac:kACMHMACAlgMD5 key:key encoding:encoding];
}

- (NSString*) acm_hmacSHA1:(NSString*)key {
    return [self acm_hmacSHA1:key encoding:NSUTF8StringEncoding];
}

- (NSString*) acm_hmacSHA1:(NSString *)key encoding:(NSStringEncoding)encoding {
    return [self acm_hmac:kACMHMACAlgSHA1 key:key encoding:encoding];
}

- (NSString*) acm_hmacSHA224:(NSString*)key {
    return [self acm_hmacSHA224:key encoding:NSUTF8StringEncoding];
}

- (NSString*) acm_hmacSHA224:(NSString*)key encoding:(NSStringEncoding)encoding {
    return [self acm_hmac:kACMHMACAlgSHA224 key:key encoding:encoding];
}

- (NSString*) acm_hmacSHA256:(NSString*)key {
    return [self acm_hmacSHA256:key encoding:NSUTF8StringEncoding];
}

- (NSString*) acm_hmacSHA256:(NSString *)key encoding:(NSStringEncoding)encoding {
    return [self acm_hmac:kACMHMACAlgSHA256 key:key encoding:encoding];
}

- (NSString*) acm_hmacSHA384:(NSString*)key {
    return [self acm_hmacSHA384:key encoding:NSUTF8StringEncoding];
}

- (NSString*) acm_hmacSHA384:(NSString *)key encoding:(NSStringEncoding)encoding {
    return [self acm_hmac:kACMHMACAlgSHA384 key:key encoding:encoding];
}

- (NSString*) acm_hmacSHA512:(NSString*)key {
    return [self acm_hmacSHA512:key encoding:NSUTF8StringEncoding];
}

- (NSString*) acm_hmacSHA512:(NSString *)key encoding:(NSStringEncoding)encoding {
    return [self acm_hmac:kACMHMACAlgSHA512 key:key encoding:encoding];
}

@end
