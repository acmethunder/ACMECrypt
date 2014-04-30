//
//  ACMEEncode.c
//  ACMECrypt
//
//  Created by Mike De Wolfe on 2013-11-08.
//
//

#include "ACMEEncode.h"

CFStringRef ACMEBase64Encode(CFDataRef data) {
	CFStringRef final = NULL;
    
//    CFIndex dataLength = ( data ? CFDataGetLength(data) : 0 );
//    
//    if ( dataLength > 0 ) {
//        CFErrorRef error = NULL;
//        SecTransformRef  encoder = SecEncodeTransformCreate(kSecBaseEncoding, &error);
//        
//        if ( error ) {
//            CFShow(error);
//        }
//    }
	
	
	
	return final;
}

CFStringRef ACMEBase64EncodeString(CFStringRef text) { return NULL; }

#pragma mark -
#pragma mark Base 64 Decoding

//CFDataRef ACMEBase64Decode(CFStringRef base64String) { return NULL; }

CFStringRef ACMEBase64Decode(CFDataRef data) { return NULL; }
