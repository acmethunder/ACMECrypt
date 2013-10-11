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
	NSData *certData = [[NSData alloc] initWithContentsOfFile:keypath];
	SecKeyRef publickey = ACGetPublicKeyX509((__bridge CFDataRef)certData);
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
	
	NSData *encryptedJSON = (__bridge NSData *)(ACEncryptAES256(
																(__bridge CFDataRef)(jsonData),
																(__bridge CFStringRef)(self.aes256Key),
																(__bridge CFStringRef)(self.iv) ));
	XCTAssertTrue( encryptedJSON.length > 0, @"" );
	XCTAssertFalse( [encryptedJSON isEqualToData:jsonData], @"" );
	
	NSData *decryptedJSON = (__bridge NSData *)(ACDecryptAES256(
																(__bridge CFDataRef)(encryptedJSON),
																(__bridge CFStringRef)(self.aes256Key),
																(__bridge CFStringRef)(self.iv) ));
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
	NSString *md5String = (__bridge NSString*)ACDataToHEX((__bridge CFDataRef)md5Data, true);
	XCTAssertTrue( md5String.length == 32, @"" );
	
	NSString *testMD5 = [@"858be8b0c08700867c623d1960165ddd" uppercaseString];
	XCTAssertTrue( [md5String isEqualToString:testMD5], @"" );
}

-(void)testHashNilMD5 {
	NSData *data = nil;
	NSString *md5 = (__bridge NSString *)(ACGetMD5((__bridge CFDataRef)(data)));
	XCTAssertNil(md5, @"" );
}

-(void)testHashSHA1 {
	NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	
	NSData *sha1Data = (__bridge NSData*)ACGetSHA1((__bridge CFDataRef)jsonData);
	XCTAssertTrue(sha1Data.length == CC_SHA1_DIGEST_LENGTH, @"" );
	
	NSString *sha1 = (__bridge NSString*)ACDataToHEX((__bridge CFDataRef)sha1Data, true);
	XCTAssertTrue( sha1.length == (CC_SHA1_DIGEST_LENGTH * 2), @"" );
	
	NSString *sha1CHECK = [@"4304534fbae6f879ab91ea5096aa728a9efd6481" uppercaseString];
	XCTAssertEqualObjects(sha1, sha1CHECK, @"" );
}

-(void)testHashSHA224 {
	NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	
	NSData *sha224Data = (__bridge NSData*)ACGetSHA224((__bridge CFDataRef)jsonData);
	XCTAssertTrue(sha224Data.length == CC_SHA224_DIGEST_LENGTH, @"" );
	
	NSString *sha224CHECK = [@"3a85e22d843b0783be27af38dcb145678523aa83b06b0d74444830e7" uppercaseString];
	NSString *sha224String = (__bridge NSString*)ACDataToHEX((__bridge CFDataRef)sha224Data, true);
	XCTAssertEqualWithAccuracy(sha224String.length, (NSUInteger)(CC_SHA224_DIGEST_LENGTH*2), 0, @"" );
	XCTAssertEqualObjects(sha224String, sha224CHECK, @"" );
}

-(void)testHashSHA256 {
	NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	
	NSData *sha256Data = (__bridge NSData*)ACGetSHA256((__bridge CFDataRef)jsonData);
	XCTAssertTrue( sha256Data.length > 1, @"" );
	
	NSString *sha256String = (__bridge NSString*)ACDataToHEX((__bridge CFDataRef)sha256Data, true);
	XCTAssertEqualWithAccuracy( sha256String.length, (NSUInteger)(CC_SHA256_DIGEST_LENGTH * 2), 0, @"" );
	
	NSString *sha256CHECK = [@"5d572efc2336007b483c85957c75006de76d265e5ecb03d2c01f91952b79fef4" uppercaseString];
	XCTAssertEqualObjects(  sha256String, sha256CHECK, @"" );
}

-(void)testHashSHA384 {
	NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	
	NSData *sha384Data = (__bridge NSData*)ACGetSHA384((__bridge CFDataRef)jsonData);
	XCTAssert(sha384Data.length == CC_SHA384_DIGEST_LENGTH, @"" );
	
	NSString *sha384String = (__bridge NSString*)ACDataToHEX((__bridge CFDataRef)sha384Data, true);
	XCTAssertEqualWithAccuracy(sha384String.length, (NSUInteger)(CC_SHA384_DIGEST_LENGTH * 2), 0, @"" );
	
	NSString *sha384CHECK = [@"40b408ebbb3fa57855e1e43978aaea8906cd23dc6d9add183346929b014d6ae2d124cdcd3c91ff5164aa76b86c7dbf27" uppercaseString];
	XCTAssertEqualObjects(sha384String, sha384CHECK, @"" );
}

-(void)testHashSHA512 {
	NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	
	NSData *sha512Data = (__bridge NSData*)ACGetSHA512((__bridge CFDataRef)jsonData);
	XCTAssert(sha512Data.length == CC_SHA512_DIGEST_LENGTH, @"" );
	
	NSString *sha512String = (__bridge NSString*)ACDataToHEX((__bridge CFDataRef)sha512Data, true);
	XCTAssertEqualWithAccuracy(sha512String.length, (NSUInteger)(CC_SHA512_DIGEST_LENGTH * 2), 0, @"" );
	
	NSString *sha512CHECK = [@"f3e2cde42d3a094b37b296346795c1df8b04172bd4f4ae73161428bcf836a66171fa702468a871b9352f562e61369a6b30a804290c1526ea36d4fec3aa073e04" uppercaseString];
	XCTAssertEqualObjects(sha512String, sha512CHECK, @"" );
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
	
	
	NSString *md5CHECK = @"d6cc78998fe3f070eb285bb9ca9ed512";
	NSString *hexedJSON = (__bridge NSString *)ACDataToHEX((__bridge CFDataRef)hmacedJSON,TRUE);
	XCTAssertEqualObjects(hexedJSON, [md5CHECK uppercaseString], @"" );
	
	NSString *lowerHex = (__bridge NSString*)ACDataToHEX((__bridge CFDataRef)(hmacedJSON), FALSE);
	XCTAssertEqualObjects( lowerHex, md5CHECK, @"" );
}

@end
