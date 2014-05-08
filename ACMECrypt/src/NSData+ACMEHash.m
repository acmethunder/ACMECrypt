//
//  NSData+ACMEHash.m
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-05-07.
//
//

#import "NSData+ACMEHash.h"
#include "ACMEStrings.h"

#pragma mark -
#pragma mark NSData+ACMEHash

@implementation NSData (ACMEHash)

#pragma mark Main Hash Method

-(NSString*)acm_hash:(ACMHashAlg)alg {
    NSString *hashString = nil;
    if ( acm_hash_valid_algorithm(alg) ) {
        NSData *md5Data = (NSData*)CFBridgingRelease(ACMHash((__bridge CFDataRef)self, alg));
        hashString = (NSString*)CFBridgingRelease(ACMDataToHEX((__bridge CFDataRef)md5Data, false));
    }
    
    return hashString;
}

#pragma mark MD5

- (NSString*) acm_md5 {
    return [self acm_hash:ACMHashAlgMD5];
}

#pragma mark SHA

-(NSString*)acm_sha1 {
    return [self acm_hash:ACMHashAlgSHA1];
}

-(NSString*)acm_sha224 {
    return [self acm_hash:ACMHashAlgSHA224];
}

-(NSString*)acm_sha256 {
    return [self acm_hash:ACMHashAlgSHA256];
}

-(NSString*)acm_sha384 {
    return [self acm_hash:ACMHashAlgSHA384];
}

-(NSString*)acm_sha512 {
    return [self acm_hash:ACMHashAlgSHA512];
}

@end

