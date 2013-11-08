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

#pragma mark -
#pragma mark Base 64 Encoding

CFStringRef ACBase64Encode(CFDataRef data);
CFStringRef ACBase64EncodeString(CFStringRef text);

#pragma mark -
#pragma mark Base 64 Decoding

CFDataRef ACBase64Decode(CFStringRef base64String);




#endif
