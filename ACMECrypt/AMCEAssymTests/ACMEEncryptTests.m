//
//  AMCEAssymTests.m
//  AMCEAssymTests
//
//  Created by Mike De Wolfe on 2013-09-25.
//
//

#import <XCTest/XCTest.h>

#import "ACMECrypt.h"

@interface ACMEEncryptTests : XCTestCase

@property SecKeyRef publickey;
@property SecKeyRef privatekey;

@property NSString *iv;
@property NSString *aes256Key;

@end

@implementation ACMEEncryptTests

/*!
 *  @discussion
 *      This method is called before the invocation of each test method in the class.
 */
- (void)setUp {
	[super setUp];
	
	NSString *keypath = [[NSBundle bundleForClass:self.class] pathForResource:@"rsa_public_key" ofType:@"der"];
	XCTAssertTrue( keypath.length > 0, @"" );
	SecKeyRef publickey = ACGetPublicKeyX509((__bridge CFStringRef)(keypath));
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
	
	self.iv = (__bridge NSString *)(ACRandomString(16));
	self.aes256Key = @"acmethunder";
}

/*!
 *  @discussion
 *      This method is called after the invocation of each test method in the class.
 */
- (void)tearDown { [super tearDown]; }

#pragma mark -
#pragma mark Assymetric Encryption / Decryption

-(void)testSimpleAssymEncryptDecrypt {
    NSString *simpleString = @"hello, world";
    NSData *simpleData = [simpleString dataUsingEncoding:NSUTF8StringEncoding];
	NSData *encrypted = (__bridge NSData *)(ACEncrypt((__bridge CFDataRef)(simpleData), self.publickey));
	XCTAssertNotNil( encrypted, @"" );
	XCTAssertFalse( [encrypted isEqualToData:simpleData], @"" );
	
	// Make public key can not decrypt
	NSData *failData = (__bridge NSData *)(ACDecryptWithKey((__bridge CFDataRef)(encrypted), self.publickey));
	XCTAssertNil( failData, @"" );
	
	NSData *decrypted = (__bridge NSData *)(ACDecryptWithKey((__bridge CFDataRef)(encrypted), self.privatekey));
	XCTAssertTrue( decrypted.length == simpleData.length, @"" );
	NSString *decryptedString = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
	XCTAssertTrue( [decryptedString isEqualToString:simpleString], @"" );
}

-(void)testRSALargerJSON {
	NSString *jsonPath = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json"
																		ofType:@"json"];
	
	NSError *readError = 0;
	NSString *jsonString = [[NSString alloc] initWithContentsOfFile:jsonPath
														   encoding:NSUTF8StringEncoding
															  error:&readError];
	
	NSError *jsonError = 0;
	NSDictionary *json = [NSJSONSerialization JSONObjectWithData:[jsonString dataUsingEncoding:NSUTF8StringEncoding]
														 options:0
														   error:&jsonError];
	XCTAssertTrue( [json isKindOfClass:[NSDictionary class]], @"" );
	
	jsonError = 0;
	NSData *jsonData = [NSJSONSerialization dataWithJSONObject:json options:0 error:&jsonError];
	XCTAssertNil( jsonError, @"JSON Error: %@", jsonError.debugDescription );
	XCTAssertTrue( jsonData.length > 0, @"" );
	
	NSData *encryptedJSON = (__bridge NSData *)(ACEncrypt((__bridge CFDataRef)(jsonData), self.publickey));
	XCTAssertTrue( encryptedJSON.length > 0, @"" );
	
	NSData *decryptedJSON = (__bridge NSData *)(ACDecryptWithKey((__bridge CFDataRef)(encryptedJSON), self.privatekey));
	XCTAssertTrue( decryptedJSON.length > 0, @"" );
	XCTAssertTrue( [decryptedJSON isEqualToData:jsonData], @"" );
	
	NSError *newJSONError = 0;
	NSDictionary *newJSON = [NSJSONSerialization JSONObjectWithData:decryptedJSON options:0 error:&newJSONError];
	XCTAssertNil( newJSONError, @" " );
	XCTAssertTrue( [newJSON isEqualToDictionary:json], @"" );
}

#pragma mark -
#pragma mark Symmetric Encryption / Decryption

-(void)testSimpleAES256 {
	NSString *helloString = @"hello, world";
	NSData *helloData = [helloString dataUsingEncoding:NSUTF8StringEncoding];
	
	NSData *encrypted = (__bridge NSData *)(ACEncryptAES256(
															(__bridge CFDataRef)(helloData),
															(__bridge CFStringRef)(self.aes256Key),
															(__bridge CFStringRef)(self.iv)) );
	XCTAssertNotNil( encrypted, @"" );
	XCTAssertTrue( encrypted.length > 0, @"" );
	XCTAssertFalse( [encrypted isEqualToData:helloData], @"" );
	
	NSData *decrypted = (__bridge NSData *)(ACDecryptAES256(
															(__bridge CFDataRef)(encrypted),
															(__bridge CFStringRef)(self.aes256Key),
															(__bridge CFStringRef)(self.iv)) );
	XCTAssertTrue( decrypted.length > 0, @"" );
	XCTAssertFalse( [decrypted isEqualToData:encrypted], @"" );
	XCTAssertTrue( [decrypted isEqualToData:helloData], @"" );
	
	NSString *decryptedString = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
	XCTAssertTrue( [decryptedString isEqualToString:helloString], @"" );
}

-(void)testAES256EncryptLargerJSON {
	NSString *jsonPath = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json"
																		ofType:@"json"];
	
	NSError *readError = 0;
	NSString *jsonString = [[NSString alloc] initWithContentsOfFile:jsonPath
														   encoding:NSUTF8StringEncoding
															  error:&readError];
	
	NSError *jsonError = 0;
	NSDictionary *json = [NSJSONSerialization JSONObjectWithData:[jsonString dataUsingEncoding:NSUTF8StringEncoding]
														 options:0
														   error:&jsonError];
	XCTAssertTrue( [json isKindOfClass:[NSDictionary class]], @"" );
	
	jsonError = 0;
	NSData *jsonData = [NSJSONSerialization dataWithJSONObject:json options:0 error:&jsonError];
	XCTAssertNil( jsonError, @"JSON Error: %@", jsonError.debugDescription );
	XCTAssertTrue( jsonData.length > 0, @"" );
	
	NSData *encryptedJSON = (__bridge NSData *)(ACEncryptAES256((__bridge CFDataRef)(jsonData), (__bridge CFStringRef)(self.aes256Key), (__bridge CFStringRef)(self.iv) ));
	XCTAssertTrue( encryptedJSON.length > 0, @"" );
	XCTAssertFalse( [encryptedJSON isEqualToData:jsonData], @"" );
	
	NSData *decryptedJSON = (__bridge NSData *)(ACDecryptAES256((__bridge CFDataRef)(encryptedJSON), (__bridge CFStringRef)(self.aes256Key), (__bridge CFStringRef)(self.iv) ));
	XCTAssertTrue( decryptedJSON.length > 0, @"" );
	XCTAssertTrue( [decryptedJSON isEqualToData:jsonData], @"" );
	
	jsonError = 0;
	NSDictionary * newJSON = [NSJSONSerialization JSONObjectWithData:decryptedJSON options:0 error:&jsonError];
	XCTAssertNil( jsonError, @"" );
	XCTAssertTrue( [newJSON isEqualToDictionary:json], @"" );
}

#pragma mark -
#pragma mark Hashing

-(void)testHashMD5 {
	NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	
	NSData *md5Data = (__bridge NSData*)ACGetMD5((__bridge CFDataRef)jsonData);
	NSString *md5String = (__bridge NSString*)ACDataToHEX((__bridge CFDataRef)md5Data);
	XCTAssertTrue( md5String.length == 32, @"" );
	
	NSString *testMD5 = [@"858be8b0c08700867c623d1960165ddd" uppercaseString];
	XCTAssertTrue( [md5String isEqualToString:testMD5], @"" );
}

-(void)testHashNilMD5 {
	NSData *data = nil;
	NSString *md5 = (__bridge NSString *)(ACGetMD5((__bridge CFDataRef)(data)));
	XCTAssertNil(md5, @"" );
}

#pragma mark -
#pragma mark HMAC

-(void)testSignHMACMD5 {
	NSString *key = @"michaeldewolfe";
	
	NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	XCTAssertNotNil( jsonData, @"" );
	
	NSData *hmacedJSON = (__bridge id)ACHmac((__bridge CFDataRef)jsonData, (__bridge CFStringRef)key, kACHMACAlgMD5);
	XCTAssertNotNil(hmacedJSON, @"" );
	XCTAssertTrue( hmacedJSON.length > 0, @"" );
	
	
	NSString *md5CHECK = [@"d6cc78998fe3f070eb285bb9ca9ed512" uppercaseString];
	NSString *hexedJSON = (__bridge NSString *)(ACDataToHEX((__bridge CFDataRef)(hmacedJSON)));
	XCTAssertEqualObjects(hexedJSON, md5CHECK, @"" );
}

@end
