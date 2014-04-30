//
//  ACMEHelpers.m
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-04-29.
//
//

#import "ACMEHelpers.h"

#include "ACMEHash.h"
#include "ACMEStrings.h"


@implementation NSString (ACMEHash)

- (NSString*) acm_md5Hash {
    NSString *md5Hash = 0;
    
    
    
    return md5Hash;
}

@end

@implementation NSData (ACMEHash)

- (NSString*) acm_md5Hash {
    NSData *md5Data = (NSData*)CFBridgingRelease(ACMHash((__bridge CFDataRef)self, ACMHashAlgMD5));
    
    NSString *md5String = (NSString*)CFBridgingRelease(ACMDataToHEX(CFBridgingRetain(md5Data), false));
    return md5String;
}

@end
