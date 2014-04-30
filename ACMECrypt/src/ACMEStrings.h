//
//  ACMEStrings.h
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-04-29.
//
//

#ifndef ACMECrypt_ACMEStrings_h
#define ACMECrypt_ACMEStrings_h

#include <CoreFoundation/CoreFoundation.h>

/*!
 *	@function
 *		ACMDataToHEX
 *	@abstract
 *		Returns a string containing the uppercase hexits of the provided CFDataRef item.
 *	@param
 *		data (CFDataRef)
 *	@param
 *		upper (bool), pass 'true' if the return value should be in uppercase, 'false' for lowercase.
 *	@return
 *		CFStringRef, 'NULL' if an error occurs.
 */
CFStringRef ACMDataToHEX(CFDataRef data, bool upper);


#endif
