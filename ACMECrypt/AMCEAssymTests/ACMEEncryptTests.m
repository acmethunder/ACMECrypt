//
//  AMCEAssymTests.m
//  AMCEAssymTests
//
//  Created by Mike De Wolfe on 2013-09-25.
//
//

#import <XCTest/XCTest.h>

#import "ACMECrypt.h"
#import "ACMEEncode.h"
#import "ACMEAdditions.h"

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
	SecKeyRef publickey = ACMGetPublicKeyX509((__bridge CFDataRef)certData);
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
	
	self.iv = (__bridge NSString *)(ACMRandomString(16));
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
	NSData *encrypted = (__bridge NSData *)(ACMEncrypt((__bridge CFDataRef)(simpleData), self.publickey));
	XCTAssertNotNil( encrypted, @"" );
	XCTAssertFalse( [encrypted isEqualToData:simpleData], @"" );
	
	// Make public key can not decrypt
	NSData *failData = (__bridge NSData *)(ACMDecryptWithKey((__bridge CFDataRef)(encrypted), self.publickey));
	XCTAssertNil( failData, @"" );
	
	NSData *decrypted = (__bridge NSData *)(ACMDecryptWithKey((__bridge CFDataRef)(encrypted), self.privatekey));
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
	NSData *json_data = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
	NSDictionary *json = [NSJSONSerialization JSONObjectWithData:json_data
														 options:0
														   error:&jsonError];
	XCTAssertTrue( [json isKindOfClass:[NSDictionary class]], @"" );
	
	jsonError = 0;
	NSData *jsonData = [NSJSONSerialization dataWithJSONObject:json options:0 error:&jsonError];
	XCTAssertNil( jsonError, @"JSON Error: %@", jsonError.debugDescription );
	XCTAssertTrue( jsonData.length > 0, @"" );
	
	NSData *encryptedJSON = (__bridge NSData *)(ACMEncrypt((__bridge CFDataRef)(jsonData), self.publickey));
	XCTAssertTrue( encryptedJSON.length > 0, @"" );
	
	NSData *decryptedJSON = (__bridge NSData *)(ACMDecryptWithKey((__bridge CFDataRef)(encryptedJSON), self.privatekey));
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
	
	NSData *encrypted = (__bridge NSData *)(ACMEncryptAES256(
															(__bridge CFDataRef)(helloData),
															(__bridge CFStringRef)(self.aes256Key),
															(__bridge CFStringRef)(self.iv)) );
	XCTAssertNotNil( encrypted, @"" );
	XCTAssertTrue( encrypted.length > 0, @"" );
	XCTAssertFalse( [encrypted isEqualToData:helloData], @"" );
	
	NSData *decrypted = (__bridge NSData *)(ACMDecryptAES256(
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
	
	NSData *encryptedJSON = (__bridge NSData *)(ACMEncryptAES256(
																(__bridge CFDataRef)(jsonData),
																(__bridge CFStringRef)(self.aes256Key),
																(__bridge CFStringRef)(self.iv) ));
	XCTAssertTrue( encryptedJSON.length > 0, @"" );
	XCTAssertFalse( [encryptedJSON isEqualToData:jsonData], @"" );
	
	NSData *decryptedJSON = (__bridge NSData *)(ACMDecryptAES256(
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
#pragma mark HASHING
#pragma mark -

#pragma mark Nil Tests

-(void)testNilHash {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    
    XCTAssertNil( [jsonData acm_hash:ACMHashAlgMD5 - 1], @"Should be \'nil.\'" );
    XCTAssertNil( [jsonData acm_hash:ACMHashAlgSHA512 + 1], @"Should be \'nil.\'" );
}

#pragma mark MD5

static NSString * const kTestMD5 = @"858be8b0c08700867c623d1960165ddd";

-(void)testHashNilMD5 {
	NSData *data = nil;
	NSString *md5 = (__bridge NSString *)(ACMHash((__bridge CFDataRef)data,0));
	XCTAssertNil(md5, @"" );
}

/*!
 *	@discussion
 *		Check hash generated via Terminal:
 *			> md5 ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
-(void)testGenericHash {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	
	NSData *md5Data = (__bridge NSData*)ACMHash((__bridge CFDataRef)(jsonData), ACMHashAlgMD5);
	NSString *md5String = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)md5Data, true);
	XCTAssertTrue( md5String.length == 32, @"" );
	
	NSString *testMD5 = [kTestMD5 uppercaseString];
	XCTAssertTrue( [md5String isEqualToString:testMD5], @"" );
}

- (void)testMD5OnNSData {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    XCTAssertNotNil( jsonData, @"" );
    
    NSString *json_md5 = [jsonData acm_md5];
    XCTAssertTrue(
                  [json_md5 isKindOfClass:[NSString class]],
                  @"Is actually instance of \'%@.\'",
                  NSStringFromClass([json_md5 class]) );
    NSString *testMD5 = kTestMD5;
    XCTAssertEqualObjects( json_md5, testMD5, @"Should logically equal strings." );
}

-(void)testMD5OnNSString {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    
    NSString *json_string = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSString *md5String = [json_string acm_md5];
    XCTAssertEqualObjects(md5String, kTestMD5, @"" );
}

/**
 *  @discussion
 *      Sample string from: https://dev.twitter.com/docs/auth/creating-signature
 */
static NSString * const kTwtrSignatureBaseString = @"POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521";

/**
 *  @discussion
 *      genertated via: >md5 -s <kTwtrSignatureBaseString>
 */
static NSString * const kTwtrMD5 = @"00ab4d53dbe9900a3ac2a61201be5290";

-(void)testMD5TwitterExample {
    NSString *twtrMD5 = [kTwtrSignatureBaseString acm_md5];
    XCTAssertEqualObjects( kTwtrMD5, twtrMD5, @"" );
}

#pragma mark SHA1

static NSString * const kSHA1Check = @"4304534fbae6f879ab91ea5096aa728a9efd6481";

/*!
 *	@discussion
 *		Check hash generated via Terminal:
 *			> shasum ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
-(void)testGenericHashSHA1 {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	
	NSData *sha1Data = (__bridge NSData*)ACMHash((__bridge CFDataRef)(jsonData), ACMHashAlgSHA1);
	XCTAssertTrue(sha1Data.length == CC_SHA1_DIGEST_LENGTH, @"" );
	
	NSString *sha1 = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)sha1Data, true);
	XCTAssertTrue( sha1.length == (CC_SHA1_DIGEST_LENGTH * 2), @"" );
	
	NSString *sha1CHECK = [kSHA1Check uppercaseString];
	XCTAssertEqualObjects(sha1, sha1CHECK, @"" );
}

-(void)testSHA1OnNSData {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    
    NSString *sha1String = [jsonData acm_sha1];
    XCTAssertEqualObjects( sha1String, kSHA1Check, @"SHould be logically equal." );
}

-(void)testSHA1OnNSString {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    
    NSString *json_string = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSString *sha1String = [json_string acm_sha1];
    XCTAssertEqualObjects(sha1String, kSHA1Check, @"" );
}

/**
 *  @discussion
 *      Generated via > echo -n "<kTwtrSignatureBaseString>" | shasum
 */
static NSString * const kTwtrSHA1 = @"996eeac5353ddfac330dc6562f2d6d491db6623d";

-(void)testSAH1OnTWitterExample {
    NSString *twtrSAH1 = [kTwtrSignatureBaseString acm_sha1];
    XCTAssertEqualObjects( twtrSAH1, kTwtrSHA1, @"" );
}

#pragma mark SHA224

static NSString * const kSha224Check = @"3a85e22d843b0783be27af38dcb145678523aa83b06b0d74444830e7";

/*!
 *	@discussion
 *		check hash generated via Terminal:
 *			> shasum -a 224 ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
-(void)testGenericHashSHA224 {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	
	NSData *sha224Data = (__bridge NSData*)ACMHash((__bridge CFDataRef)(jsonData),ACMHashAlgSHA224);
	XCTAssertTrue(sha224Data.length == CC_SHA224_DIGEST_LENGTH, @"" );
	
	NSString *sha224CHECK = [kSha224Check uppercaseString];
	NSString *sha224String = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)sha224Data, true);
	XCTAssertEqualWithAccuracy(sha224String.length, (NSUInteger)(CC_SHA224_DIGEST_LENGTH*2), 0, @"" );
	XCTAssertEqualObjects(sha224String, sha224CHECK, @"" );
}

-(void)testSHA224OnNSData {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    
    NSString *sha224String = [jsonData acm_sha224];
    XCTAssertEqualObjects( sha224String, kSha224Check, @"Should be logically equal." );
}

-(void)testSHA224OnNSString {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    
    NSString *json_string = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSString *sha224String = [json_string acm_sha224];
    XCTAssertEqualObjects(sha224String, kSha224Check, @"" );
}

/**
 *  @discussion
 *      Generated via >echo -n "<kTwtrSignatureBaseString>" | shasum -a 224
 */
static NSString * const kTwtrSHA224 = @"8f4c547b94d96d7cfe27862b94200f31e440300f0fc605ddfd61deeb";

-(void)testSHA22OnTwitterExample {
    NSString *sha224String = [kTwtrSignatureBaseString acm_sha224];
    XCTAssertEqualObjects( sha224String, kTwtrSHA224, @"" );
}

#pragma mark SHA256

static NSString * const kSHA256Check = @"5d572efc2336007b483c85957c75006de76d265e5ecb03d2c01f91952b79fef4";

/*!
 *	@discussion
 *		check hash generated via Terminal:
 *			> shasum -a 256 ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
-(void)testGenericHashSHA256 {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	
	NSData *sha256Data = (__bridge NSData*)ACMHash((__bridge CFDataRef)jsonData, ACMHashAlgSHA256);
	XCTAssertTrue( sha256Data.length > 1, @"" );
	
	NSString *sha256String = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)sha256Data, true);
	XCTAssertEqualWithAccuracy( sha256String.length, (NSUInteger)(CC_SHA256_DIGEST_LENGTH * 2), 0, @"" );
	
	NSString *sha256CHECK = [kSHA256Check uppercaseString];
	XCTAssertEqualObjects(  sha256String, sha256CHECK, @"" );
}

-(void)testSHA256OnNSData {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    
    NSString *sha256String = [jsonData acm_sha256];
    XCTAssertEqualObjects( sha256String, kSHA256Check, @"" );
}

-(void)testSHA256OnNSString {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    
    NSString *json_string = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSString *sha256String = [json_string acm_sha256];
    XCTAssertEqualObjects(sha256String, kSHA256Check, @"" );
}

/**
 *  @discussion
 *      Generated via >echo -n "<kTwtrSignatureBaseString>" | shasum -a 256
 */
static NSString * const kTwtrSHA256 = @"22b08fd1867b58f7ebf8a86949c7faaca2ceb814782b3b860d107754682636e2";

-(void)testSHA256OnTWitterExample {
    NSString *sha256_string = [kTwtrSignatureBaseString acm_sha256];
    XCTAssertEqualObjects( sha256_string, kTwtrSHA256, @"" );
}

#pragma mark SHA384

static NSString * const kSHA384Check = @"40b408ebbb3fa57855e1e43978aaea8906cd23dc6d9add183346929b014d6ae2d124cdcd3c91ff5164aa76b86c7dbf27";

/*!
 *	@discussion
 *		check hash generated via Terminal:
 *			> shasum -a 384 ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
-(void)testGenericHashSHA384 {
   	NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	
	NSData *sha384Data = (__bridge NSData*)ACMHash((__bridge CFDataRef)jsonData,ACMHashAlgSHA384);
	XCTAssert(sha384Data.length == CC_SHA384_DIGEST_LENGTH, @"" );
	
	NSString *sha384String = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)sha384Data, true);
	XCTAssertEqualWithAccuracy(sha384String.length, (NSUInteger)(CC_SHA384_DIGEST_LENGTH * 2), 0, @"" );
	
	NSString *sha384CHECK = [kSHA384Check uppercaseString];
	XCTAssertEqualObjects(sha384String, sha384CHECK, @"" );
}

-(void)testSHA384OnNSData {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    
    NSString *sha384String = [jsonData acm_sha384];
    XCTAssertEqualObjects( sha384String, kSHA384Check, @"" );
}

-(void)testSHA384OnNSString {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    
    NSString *json_string = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSString *sha384_string = [json_string acm_sha384];
    XCTAssertEqualObjects(sha384_string, kSHA384Check, @"" );
}

/**
 *  @discussion
 *      Generated via >echo -n "<kTwtrSignatureBaseString>" | shasum -a 384
 */
static NSString * const kTwtrSHA384 = @"881bccbcffc7ba471ea00b2f1d8cd15a32b6527ead53fe22482b745ee283406d0c62263cbba8d9f6b64dfdcbb092d8e6";

-(void)testSHA384OnTwitterExample {
    NSString *sha384_string = [kTwtrSignatureBaseString acm_sha384];
    XCTAssertEqualObjects( sha384_string, kTwtrSHA384, @"" );
}

#pragma mark SHA512

static NSString * const kSHA512Check = @"f3e2cde42d3a094b37b296346795c1df8b04172bd4f4ae73161428bcf836a66171fa702468a871b9352f562e61369a6b30a804290c1526ea36d4fec3aa073e04";

/*!
 *	@discussion
 *		check hash generated via Terminal:
 *			> shasum -a 512 ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
-(void)testGenericHashSHA512 {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	
	NSData *sha512Data = (__bridge NSData*)ACMHash((__bridge CFDataRef)jsonData, ACMHashAlgSHA512);
	XCTAssert(sha512Data.length == CC_SHA512_DIGEST_LENGTH, @"" );
	
	NSString *sha512String = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)sha512Data, true);
	XCTAssertEqualWithAccuracy(sha512String.length, (NSUInteger)(CC_SHA512_DIGEST_LENGTH * 2), 0, @"" );
	
	NSString *sha512CHECK = [kSHA512Check uppercaseString];
	XCTAssertEqualObjects(sha512String, sha512CHECK, @"" );
}

-(void)testSHA512OnNSData {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    
    NSString *sha512String = [jsonData acm_sha512];
    XCTAssertEqualObjects( sha512String, kSHA512Check, @"" );
}

-(void)testSHA512OnNSString {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    
    NSString *json_string = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSString *sha512_string = [json_string acm_sha512];
    XCTAssertEqualObjects(sha512_string, kSHA512Check, @"" );
}

/**
 *  @discussion
 *      Generated via >echo -n "<kTwtrSignatureBaseString>" | shasum -a 512
 */
static NSString * const kTwtrSHA512 = @"2587b48845dfd32afad49274bebe036df7a2224885cae4cd91eb21a3d1445203196ea5ec48c0885c8de29f09479e4ecebd6d9b1d63be4fd7d9d9a29f7d9db070";

-(void)testSHA512onTwitterexample {
    NSString *sha512_string = [kTwtrSignatureBaseString acm_sha512];
    XCTAssertEqualObjects( sha512_string, kTwtrSHA512, @"" );
}

#pragma mark -
#pragma mark HMAC

/*!
 *	@discussion
 *		Signature generated via Terminal:
 *			> openssl dgst -md5 -hmac "qwertyazerty" ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
-(void)testSignHMACMD5 {
	NSString *key = @"qwertyazerty";
	
	NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
	XCTAssertNotNil( jsonData, @"" );
	
	NSData *hmacedJSON = (__bridge id)ACMHmac((__bridge CFDataRef)jsonData, (__bridge CFStringRef)key, kACHMACAlgMD5);
	XCTAssertNotNil(hmacedJSON, @"" );
	XCTAssertTrue( hmacedJSON.length > 0, @"" );
	
	
	NSString *md5CHECK = @"ddb67a34c3f54728ef3130fbf2031498";
	NSString *hexedJSON = (__bridge NSString *)ACMDataToHEX((__bridge CFDataRef)hmacedJSON,TRUE);
	XCTAssertEqualObjects(hexedJSON, [md5CHECK uppercaseString], @"" );
	
	NSString *lowerHex = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)(hmacedJSON), FALSE);
	XCTAssertEqualObjects( lowerHex, md5CHECK, @"" );
}

/*!
 *	@discussion
 *		Signature generated via Terminal:
 *			> openssl dgst -sha1 -hmac "qwertyazerty" ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
-(void)testSignHAMCSHA1 {
    NSString *key = @"qwertyazerty";
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    NSData *hmacedJSON = (__bridge id)ACMHmac((__bridge CFDataRef)jsonData, (__bridge CFStringRef)key, kACHMACAlgSHA1);
    
    XCTAssertNotNil(hmacedJSON, @"" );
	XCTAssertTrue( hmacedJSON.length > 0, @"" );

	NSString *sha1Check = @"b82f69844a68cdc6daf8a4235d34ede793bfb274";
	NSString *hexedJSON = (__bridge NSString *)ACMDataToHEX((__bridge CFDataRef)hmacedJSON,TRUE);
	XCTAssertEqualObjects(hexedJSON, [sha1Check uppercaseString], @"" );
	
	NSString *lowerHex = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)(hmacedJSON), FALSE);
	XCTAssertEqualObjects( lowerHex, sha1Check, @"" );
}

#pragma mark -
#pragma mark Base 64 Encoding

//-(void)testBase64EncodeData {
//	NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
//	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
//	XCTAssertNotNil( jsonData, @"" );
//	
//	NSString *base64String = CFBridgingRelease(ACBase64Encode((__bridge CFDataRef)(jsonData)));
//	XCTAssertFalse( base64String, @"" );
//}

@end
