
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
#include "ACMECrypt.h"

@interface ACMESignTests : XCTestCase

@property NSData *sampleData;
@property SecKeyRef privateKey;
@property SecKeyRef publicKey;

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
    
    NSURL *keypath = [bundle URLForResource:@"rsa_public_key" withExtension:@"der"];
    NSData *certData = [[NSData alloc] initWithContentsOfURL:keypath];
    SecKeyRef publickey = ACMGetPublicKeyX509((__bridge CFDataRef)certData);
    XCTAssertFalse( publickey == NULL, @"" );
    self.publicKey = publickey;
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
    
    CFRelease(self.privateKey);
    CFRelease(self.publicKey);
}

#pragma mark RSA Signature

- (void) testSanityCheck {
    NSData *sampleData = self.sampleData;
    SecKeyRef privateKey = self.privateKey;
    NSData *hashData = CFBridgingRelease(ACMHash((__bridge CFDataRef)(sampleData), ACMHashAlgSHA256));
    NSData *signature = CFBridgingRelease(acme_sign_hash_data(
                                                              (__bridge CFDataRef)(hashData),
                                                              kSecPaddingPKCS1SHA256,
                                                              (__bridge CFDataRef)(sampleData),
                                                              privateKey) );
    XCTAssertNotNil( signature );

    SecKeyRef publicKey = self.publicKey;
    bool verified = acme_verify_hash_data(
                                          (__bridge CFDataRef)(hashData),
                                          kSecPaddingPKCS1SHA256,
                                          (__bridge CFDataRef)(signature),
                                          publicKey );
    XCTAssertTrue( verified );
}

- (void) testSHA1SignAndVerify {
    NSData *sampleData = self.sampleData;
    SecKeyRef privateKey = self.privateKey;
    NSData *signature = (__bridge NSData *)(acme_sha1_sign((__bridge CFDataRef)(sampleData), privateKey));
    XCTAssertNotNil( signature );

    SecKeyRef publicKey = self.publicKey;
    bool verified = acme_verify_sha1((__bridge CFDataRef)(sampleData), (__bridge CFDataRef)(signature), publicKey);
    XCTAssertTrue( verified );
}

- (void) testSHA224SignAndVerify {
    NSData *sampleData = self.sampleData;
    SecKeyRef privateKey = self.privateKey;
    NSData *signature = CFBridgingRelease(acme_sha224_sign((__bridge CFDataRef)(sampleData), privateKey));
    XCTAssertNotNil( signature );

    SecKeyRef publicKey = self.publicKey;
    bool verified = acme_verify_sha224((__bridge CFDataRef)(sampleData), (__bridge CFDataRef)(signature), publicKey);
    XCTAssertTrue( verified );
}

- (void) testSHA256SignAndVerify {
    NSData *sampleData = self.sampleData;
    SecKeyRef privateKey = self.privateKey;
    NSData *signature = CFBridgingRelease(acme_sha256_sign((__bridge CFDataRef)(sampleData), privateKey));
    XCTAssertNotNil( signature );

    SecKeyRef publicKey = self.publicKey;
    bool verified = acme_verify_sha256((__bridge CFDataRef)(sampleData), (__bridge CFDataRef)(signature), publicKey);
    XCTAssertTrue( verified );
}

- (void) testSignSHA384SignAndVerify {
    SecKeyRef privateKey = self.privateKey;
    NSData *sampleData = self.sampleData;
    NSData *signature = CFBridgingRelease(acme_sha384_sign((__bridge CFDataRef)(sampleData), privateKey));
    XCTAssertNotNil( signature );

    SecKeyRef publicKey = self.publicKey;
    bool verified = acme_verify_sha384((__bridge CFDataRef)(sampleData), (__bridge CFDataRef)(signature), publicKey);
    XCTAssertTrue( verified );
}

- (void) testSHA512SignandVerify {
    NSData *sampleData = self.sampleData;
    SecKeyRef privateKey = self.privateKey;
    NSData *signature = CFBridgingRelease(acme_sha512_sign((__bridge CFDataRef)(sampleData), privateKey));
    XCTAssertNotNil( signature );

    SecKeyRef publicKey = self.publicKey;
    bool verified = acme_verify_sha512((__bridge CFDataRef)(sampleData), (__bridge CFDataRef)(signature), publicKey);
    XCTAssertTrue( verified );
}
@end
