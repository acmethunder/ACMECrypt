//
//  ACMEHelpers.m
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-04-29.
//
//

#import "ACMEHelpers.h"

#include "ACMEStrings.h"

#pragma mark -
#pragma mark NSString+ACMEHash

@implementation NSString (ACMEHash)

#pragma mark MD5

- (NSString*) acm_md5Hash {
    NSString *md5Hash = [self acm_md5HashWithEncoding:NSUTF8StringEncoding];
    return md5Hash;
}

- (NSString*) acm_md5HashWithEncoding:(NSStringEncoding)encoding {
    NSData *data  = [self dataUsingEncoding:encoding];
    NSString *md5 = [data acm_md5Hash];
    return md5;
}

@end

#pragma mark -
#pragma mark NSData+ACMEHash

@implementation NSData (ACMEHash)

#pragma mark Main Hash Method

-(NSString*)acm_hash:(ACMHashAlg)alg {
    
    NSString *hashString = nil;
    if ( (alg >= ACMHashAlgMD5) && (alg <= ACMHashAlgSHA512) ) {
        NSData *md5Data = (NSData*)CFBridgingRelease(ACMHash((__bridge CFDataRef)self, alg));
        hashString = (NSString*)CFBridgingRelease(ACMDataToHEX((__bridge CFDataRef)md5Data, false));
    }
    
    
    return hashString;
}

#pragma mark MD5

- (NSString*) acm_md5Hash {
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
