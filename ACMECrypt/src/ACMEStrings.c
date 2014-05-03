//
//  ACMEStrings.c
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-04-29.
//
//

#include "ACMEStrings.h"

static const char *kACryptHEXFormatUpper  = "%02X";
static const char *kACCryptHEXFormatLower = "%02x";

#pragma mark -
#pragma mark To String

CFStringRef ACMDataToHEX(CFDataRef data, bool upper) {
	CFStringRef final = NULL;
	
	CFIndex dataLength = ( data ? CFDataGetLength(data) : 0 );
	
	if ( dataLength >  0 ) {
		const UInt8 *dataptr = CFDataGetBytePtr(data);
		
		CFMutableStringRef temp = CFStringCreateMutable(kCFAllocatorDefault, dataLength * 2);
		const char *formattype  = ( upper ? kACryptHEXFormatUpper : kACCryptHEXFormatLower );
		CFStringRef format      = CFStringCreateWithCString(
                                                            kCFAllocatorDefault,
                                                            formattype,
                                                            kCFStringEncodingUTF8 );
		
		for ( int i = 0; i < dataLength; ++i ) {
			CFStringAppendFormat(temp, NULL, format, dataptr[i]);
		}
		
		if ( format ) {
			CFRelease(format);
		}
		
		if ( temp ) {
			final = CFStringCreateCopy(kCFAllocatorDefault, temp);
			CFRelease(temp);
		}
	}
    
	return final;
}
