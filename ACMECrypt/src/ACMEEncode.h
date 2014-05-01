//
//  ACMEEncode.h
//  ACMECrypt
//
//  Created by Mike De Wolfe on 2013-11-08.
//
//

#ifndef ACMECrypt_ACMEEncode_h
#define ACMECrypt_ACMEEncode_h

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

CF_EXTERN_C_BEGIN

#pragma mark -
#pragma mark Base 64 Encoding

CFStringRef ACMEBase64Encode(CFDataRef data);
CFStringRef ACMEBase64EncodeString(CFStringRef text);

#pragma mark -
#pragma mark Base 64 Decoding

//CFDataRef ACMEBase64DecodeString(CFStringRef base64String);
CFStringRef ACMEBase64Decode(CFDataRef data);


CF_EXTERN_C_END

#endif
