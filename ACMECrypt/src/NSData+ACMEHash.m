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

- (NSData*) acm_hashRaw:(ACMHashAlg)alg {
    return ( acm_hash_valid_algorithm(alg) ? CFBridgingRelease(ACMHash((__bridge CFDataRef)(self), alg)) : nil );
}

-(NSString*)acm_hash:(ACMHashAlg)alg {
    NSString *hashString = nil;
    if ( acm_hash_valid_algorithm(alg) ) {
        NSData *md5Data = (NSData*)CFBridgingRelease(ACMHash((__bridge CFDataRef)self, alg));
        hashString = (NSString*)CFBridgingRelease(ACMDataToHEX((__bridge CFDataRef)md5Data, false));
    }
    
    return hashString;
}

- (NSString*) acm_toHex {
    return CFBridgingRelease(ACMDataToHEX((__bridge CFDataRef)(self), false));
}

#pragma mark MD5

- (NSData*) acm_MD5Raw {
    return [self acm_hashRaw:ACMHashAlgMD5];
}

- (NSString*) acm_md5 {
    NSData *temp = [self acm_MD5Raw];
    return [temp acm_toHex];
}

#pragma mark SHA

- (NSData*) acm_sha1Raw {
    return [self acm_hashRaw:ACMHashAlgSHA1];
}

-(NSString*)acm_sha1 {
    NSData *temp = [self acm_sha1Raw];
    return [temp acm_toHex];
}

- (NSData*) acm_sha224Raw {
    return [self acm_hashRaw:ACMHashAlgSHA224];
}

-(NSString*)acm_sha224 {
    NSData *temp = [self acm_sha224Raw];
    return [temp acm_toHex];
}

- (NSData*) acm_sha256Raw {
    return [self acm_hashRaw:ACMHashAlgSHA256];
}

-(NSString*)acm_sha256 {
    NSData *temp = [self acm_sha256Raw];
    return [temp acm_toHex];
}

- (NSData*) acm_sha384Raw {
    return [self acm_hashRaw:ACMHashAlgSHA384];
}

-(NSString*)acm_sha384 {
    NSData *temp = [self acm_sha384Raw];
    return [temp acm_toHex];
}

- (NSData*) acm_sha512Raw {
    return [self acm_hashRaw:ACMHashAlgSHA512];
}

-(NSString*)acm_sha512 {
    NSData *temp = [self acm_sha512Raw];
    return [temp acm_toHex];
}

@end

