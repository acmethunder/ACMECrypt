//
//  NSData+ACMESign.m
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2015-07-05.
//
//

#import "NSData+ACMESign.h"

#import "NSData+ACMEHash.h"
#import "ACMESign.h"

static SecPadding _acm_padding_for_alg(ACMHashAlg alg) {
    SecPadding padding;
    switch ( alg ) {
        case ACMHashAlgSHA1:
            padding = kSecPaddingPKCS1SHA1;
            break;
        case ACMHashAlgSHA224:
            padding = kSecPaddingPKCS1SHA224;
            break;
        case ACMHashAlgSHA256:
            padding = kSecPaddingPKCS1SHA256;
            break;
        case ACMHashAlgSHA384:
            padding = kSecPaddingPKCS1SHA384;
            break;
        case ACMHashAlgSHA512:
            padding = kSecPaddingPKCS1SHA512;
            break;
        case ACMHashAlgMD5:
        default:
            padding = kSecPaddingPKCS1MD5;
            break;
    }

    return padding;
}

@implementation NSData (ACMESign)

- (NSData*) acm_sign:(ACMHashAlg)hashAlg key:(SecKeyRef)key {
    NSData *hash = [self acm_hashRaw:hashAlg];

    NSData *signature = nil;
    if ( hash ) {
        SecPadding padding = _acm_padding_for_alg(hashAlg);
        signature = CFBridgingRelease(acme_sign_hash_data(
                                                          (__bridge CFDataRef)(hash),
                                                          padding,
                                                          (__bridge CFDataRef)(self),
                                                          key) );
    }

    return signature;
}

- (NSData*) acm_sha1Sign:(SecKeyRef)key {
    return [self acm_sign:ACMHashAlgSHA1 key:key];
}

@end
