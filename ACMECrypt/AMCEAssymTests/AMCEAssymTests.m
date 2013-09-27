//
//  AMCEAssymTests.m
//  AMCEAssymTests
//
//  Created by Mike De Wolfe on 2013-09-25.
//
//

#import <XCTest/XCTest.h>

#import "ACMEAssymCrypt.h"

@interface AMCEAssymTests : XCTestCase

@property SecKeyRef publickey;
@property SecKeyRef privatekey;

@end

@implementation AMCEAssymTests

/*!
 *  @discussion
 *      This method is called before the invocation of each test method in the class.
 */
- (void)setUp {
	[super setUp];
	
	NSString *keypath = [[NSBundle bundleForClass:self.class] pathForResource:@"rsa_public_key" ofType:@"der"];
	XCTAssertTrue( keypath.length > 0, @"" );
	SecKeyRef publickey = ACGetPublicKeyX509(keypath);
	XCTAssertFalse( publickey == NULL, @"" );
	self.publickey = publickey;
	
	
	NSString *privatekeypath = [[NSBundle bundleForClass:self.class] pathForResource:@"rsa_private_key" ofType:@"p12"];
	NSData *p12Data = [[NSData alloc] initWithContentsOfFile:privatekeypath];
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
		self.privatekey = privateKey;
	}
}

/*!
 *  @discussion
 *      This method is called after the invocation of each test method in the class.
 */
- (void)tearDown { [super tearDown]; }

-(void)testSimpleAssymEncryptDecrypt {
    NSString *simpleString = @"hello, world";
    NSData *simpleData = [simpleString dataUsingEncoding:NSUTF8StringEncoding];
	NSData *encrypted = ACEncrypt(simpleData, self.publickey);
	XCTAssertNotNil( encrypted, @"" );
	XCTAssertFalse( [encrypted isEqualToData:simpleData], @"" );
	
	NSData *decrypted = ACDecryptWithKey(encrypted, self.privatekey);
	XCTAssertTrue( decrypted.length == simpleData.length, @"" );
	NSString *decryptedString = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
	XCTAssertTrue( [decryptedString isEqualToString:simpleString], @"" );
	

}

@end
