//
//  ACMEHelpMe.m
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2014-05-04.
//
//

#import "ACMEHelpMe.h"

BOOL acm_valid_encoding(NSStringEncoding enc) {
    BOOL isGood;
    
    switch ( enc ) {
        case NSASCIIStringEncoding             :
        case NSNEXTSTEPStringEncoding          :
        case NSJapaneseEUCStringEncoding       :
        case NSUTF8StringEncoding              :
        case NSISOLatin1StringEncoding         :
        case NSSymbolStringEncoding            :
        case NSNonLossyASCIIStringEncoding     :
        case NSShiftJISStringEncoding          :
        case NSISOLatin2StringEncoding         :
        case NSUnicodeStringEncoding           :
        case NSWindowsCP1251StringEncoding     :
        case NSWindowsCP1252StringEncoding     :
        case NSWindowsCP1253StringEncoding     :
        case NSWindowsCP1254StringEncoding     :
        case NSWindowsCP1250StringEncoding     :
        case NSISO2022JPStringEncoding         :
        case NSMacOSRomanStringEncoding        :
        case NSUTF16BigEndianStringEncoding    :
        case NSUTF16LittleEndianStringEncoding :
        case NSUTF32StringEncoding             :
        case NSUTF32BigEndianStringEncoding    :
        case NSUTF32LittleEndianStringEncoding : isGood = TRUE;
            break;
        default : isGood = FALSE;
            break;
    }
    
    return isGood;
}
