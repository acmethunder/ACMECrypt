//
//  ACMEHelpMe.h
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-05-04.
//
//

@import Foundation;

CF_EXTERN_C_BEGIN

/**
 *  @name
 *      Validation
 *  @function
 *      acm_valid_encoding
 *  @brief
 *      Validates the given encoding.
 *  @discussion
 *      All encodings listed under 'NSStringEncoding' are considered valid.
 *  @param
 *      enc (NSStringEncoding), encoding to validate.
 *  @return
 *      'true' if 'enc' is equal to any values listed under 'NSStringEncoding.' 'false' otherwise.
 *  @see
 *      NSString.h for list of encoding values.
 */
BOOL acm_valid_encoding(NSStringEncoding enc);

CF_EXTERN_C_END
