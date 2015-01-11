//
//  ACMESignTests.m
//  ACMECrypt
//
//  Created by Michael De Wolfe on 2015-01-08.
//
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#include "ACMERSASign.h"
#include "ACMEHash.h"

@interface ACMESignTests : XCTestCase

@property NSData *sampleData;
@property SecKeyRef privateKey;

@end

@implementation ACMESignTests

- (void)setUp {
    [super setUp];
    
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    NSURL *url = [bundle URLForResource:@"sample_large_json" withExtension:@"json"];
    NSData *data = [[NSData alloc] initWithContentsOfURL:url];
    XCTAssertNotNil( data );
    self.sampleData = data;
    
    NSURL *privatekeyURL = [bundle URLForResource:@"rsa_private_key" withExtension:@"p12"];
    NSData *p12Data = [[NSData alloc] initWithContentsOfURL:privatekeyURL];
    XCTAssertFalse( p12Data.length < 1, @"" );
    
    NSMutableDictionary *options = [NSMutableDictionary new];
    [options setObject:@"miked" forKey:(__bridge id)kSecImportExportPassphrase];
    
    SecKeyRef privateKey = NULL;
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus status = SecPKCS12Import((__bridge CFDataRef)(p12Data), (__bridge CFDictionaryRef)(options), &items);
    XCTAssertEqualWithAccuracy( status, (OSStatus)0, 0, @"" );
    XCTAssert( CFArrayGetCount(items) > 0, @"" );
    
    if ( (status == noErr) && (CFArrayGetCount(items) > 0) ) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        
        status = SecIdentityCopyPrivateKey(identityApp, &privateKey);
        XCTAssertEqualWithAccuracy( status, (OSStatus)0, 0, @"" );
        XCTAssertFalse( privateKey == NULL, @"" );
        self.privateKey = privateKey;
    }
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
    
    CFRelease(self.privateKey);
}

#pragma mark RSA Signature

- (void) testSanityCheck {
    NSData *sampleData = self.sampleData;
    NSData *hashedData = CFBridgingRelease(ACMHash((__bridge CFDataRef)(sampleData), ACMHashAlgSHA256));
    XCTAssertNotNil( hashedData );
    SecKeyRef privateKey = self.privateKey;
    CFDataRef signedRaw = acme_sign_data((__bridge CFDataRef)(hashedData), kSecPaddingPKCS1SHA256, privateKey);
    NSData *signedData = CFBridgingRelease(signedRaw);
    XCTAssertNotNil( signedData );
}

@end
