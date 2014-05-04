//
//  ACMEHmacAdditions.m
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-05-04.
//
//

#import "ACMEHmacAdditions.h"
#import "ACMEHelpMe.h"
#import "ACMEStrings.h"

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
    return [self acm_hmac:kACMHMACAlgMD5 key:key encoding:NSUTF8StringEncoding];
}

- (NSString*) acm_hmacSHA1:(NSString*)key {
    return [self acm_hmac:kACMHMACAlgSHA1 key:key encoding:NSUTF8StringEncoding];
}

@end

@implementation NSData (ACMEHMAC)

- (NSString*) acm_hmac:(ACMHMACAlgorithm)alg key:(NSString*)key {
    NSString *final = nil;
    
    if ( acm_valid_hmac_alg(alg) && [key isKindOfClass:[NSString class]] ) {
        NSData *hmacData = CFBridgingRelease(ACMHmac(
                                                     (__bridge CFDataRef)(self),
                                                     (__bridge CFStringRef)(key),
                                                     alg));
        final = CFBridgingRelease(ACMDataToHEX((__bridge CFDataRef)(hmacData), false));
    }
    
    return final;
}

- (NSString*) acm_hmacMD5:(NSString*)key {
    return [self acm_hmac:kACMHMACAlgMD5 key:key];
}

- (NSString*) acm_hmacSHA1:(NSString*)key {
    return [self acm_hmac:kACMHMACAlgSHA1 key:key];
}

- (NSString*) acm_hmacSHA224:(NSString*)key {
    return [self acm_hmac:kACMHMACAlgSHA224 key:key];
}

- (NSString*) acm_hmacSHA256:(NSString*)key {
    return [self acm_hmac:kACMHMACAlgSHA256 key:key];
}

- (NSString*) acm_hmacSHA384:(NSString*)key {
    return [self acm_hmac:kACMHMACAlgSHA384 key:key];
}

- (NSString*) acm_hmacSHA512:(NSString*)key {
    return [self acm_hmac:kACMHMACAlgSHA512 key:key];
}

@end
