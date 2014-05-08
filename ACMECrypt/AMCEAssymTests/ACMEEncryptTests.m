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
#import "ACMEHashAdditions.h"
#import "NSData+ACMEHmac.h"
#import "NSString+ACMEHmac.h"

@interface ACMEEncryptTests : XCTestCase

@property SecKeyRef publickey;
@property SecKeyRef privatekey;

@property NSString *iv;
@property NSString *aes256Key;

@property NSData *json_data;
@property NSString *json_string;

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
    
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"sample_large_json" ofType:@"json"];
	NSData *jsonData = [[NSData alloc] initWithContentsOfFile:path];
    XCTAssertNotNil( jsonData, @"" );
    XCTAssertTrue( [jsonData isKindOfClass:[NSData class]], @"" );
    XCTAssertTrue( jsonData.length > 0, @"" );
    self.json_data = jsonData;
    
    NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    XCTAssertTrue(
                  [jsonString isKindOfClass:[NSString class]],
                  @"Is actually an instance of \'%@.\'",
                  NSStringFromClass([jsonString class]) );
    XCTAssertTrue( jsonString.length > 0, @"" );
    self.json_string = jsonString;
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
#pragma mark Nil Tests

-(void)testNilHash {
    XCTAssertNil( [self.json_data acm_hash:ACMHashAlgMD5 - 1], @"Should be \'nil.\'" );
    XCTAssertNil( [self.json_data acm_hash:ACMHashAlgSHA512 + 1], @"Should be \'nil.\'" );
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
	NSData *md5Data = (__bridge NSData*)ACMHash((__bridge CFDataRef)self.json_data, ACMHashAlgMD5);
	NSString *md5String = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)md5Data, true);
	NSString *testMD5 = [kTestMD5 uppercaseString];
	XCTAssertTrue( [md5String isEqualToString:testMD5], @"" );
}

- (void)testMD5OnNSData {
    NSString *json_md5 = [self.json_data acm_md5];
    XCTAssertEqualObjects( json_md5, kTestMD5, @"Should logically equal strings." );
}

-(void)testMD5OnNSString {
    NSString *md5String = [self.json_string acm_md5];
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
	NSData *sha1Data = (__bridge NSData*)ACMHash((__bridge CFDataRef)self.json_data, ACMHashAlgSHA1);
	XCTAssertTrue(sha1Data.length == CC_SHA1_DIGEST_LENGTH, @"" );
	
	NSString *sha1 = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)sha1Data, true);
	XCTAssertTrue( sha1.length == (CC_SHA1_DIGEST_LENGTH * 2), @"" );
	
	NSString *sha1CHECK = [kSHA1Check uppercaseString];
	XCTAssertEqualObjects(sha1, sha1CHECK, @"" );
}

-(void)testSHA1OnNSData {
    NSString *sha1String = [self.json_data acm_sha1];
    XCTAssertEqualObjects( sha1String, kSHA1Check, @"SHould be logically equal." );
}

-(void)testSHA1OnNSString {
    NSString *sha1String = [self.json_string acm_sha1];
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
	NSData *sha224Data = (__bridge NSData*)ACMHash((__bridge CFDataRef)self.json_data,ACMHashAlgSHA224);
	XCTAssertTrue(sha224Data.length == CC_SHA224_DIGEST_LENGTH, @"" );
	
	NSString *sha224CHECK = [kSha224Check uppercaseString];
	NSString *sha224String = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)sha224Data, true);
	XCTAssertEqualWithAccuracy(sha224String.length, (NSUInteger)(CC_SHA224_DIGEST_LENGTH*2), 0, @"" );
	XCTAssertEqualObjects(sha224String, sha224CHECK, @"" );
}

-(void)testSHA224OnNSData {
    NSString *sha224String = [self.json_data acm_sha224];
    XCTAssertEqualObjects( sha224String, kSha224Check, @"Should be logically equal." );
}

-(void)testSHA224OnNSString {
    NSString *sha224String = [self.json_string acm_sha224];
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
	NSData *sha256Data = (__bridge NSData*)ACMHash((__bridge CFDataRef)self.json_data, ACMHashAlgSHA256);
	XCTAssertTrue( sha256Data.length > 1, @"" );
	
	NSString *sha256String = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)sha256Data, true);
	XCTAssertEqualWithAccuracy( sha256String.length, (NSUInteger)(CC_SHA256_DIGEST_LENGTH * 2), 0, @"" );
	
	NSString *sha256CHECK = [kSHA256Check uppercaseString];
	XCTAssertEqualObjects(  sha256String, sha256CHECK, @"" );
}

-(void)testSHA256OnNSData {
    NSString *sha256String = [self.json_data acm_sha256];
    XCTAssertEqualObjects( sha256String, kSHA256Check, @"" );
}

-(void)testSHA256OnNSString {
    NSString *sha256String = [self.json_string acm_sha256];
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
	NSData *sha384Data = (__bridge NSData*)ACMHash((__bridge CFDataRef)self.json_data,ACMHashAlgSHA384);
	XCTAssert(sha384Data.length == CC_SHA384_DIGEST_LENGTH, @"" );
	
	NSString *sha384String = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)sha384Data, true);
	XCTAssertEqualWithAccuracy(sha384String.length, (NSUInteger)(CC_SHA384_DIGEST_LENGTH * 2), 0, @"" );
	
	NSString *sha384CHECK = [kSHA384Check uppercaseString];
	XCTAssertEqualObjects(sha384String, sha384CHECK, @"" );
}

-(void)testSHA384OnNSData {
    NSString *sha384String = [self.json_data acm_sha384];
    XCTAssertEqualObjects( sha384String, kSHA384Check, @"" );
}

-(void)testSHA384OnNSString {
    NSString *sha384_string = [self.json_string acm_sha384];
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
	NSData *sha512Data = (__bridge NSData*)ACMHash((__bridge CFDataRef)self.json_data, ACMHashAlgSHA512);
	XCTAssert(sha512Data.length == CC_SHA512_DIGEST_LENGTH, @"" );
	
	NSString *sha512String = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)sha512Data, true);
	XCTAssertEqualWithAccuracy(sha512String.length, (NSUInteger)(CC_SHA512_DIGEST_LENGTH * 2), 0, @"" );
	
	NSString *sha512CHECK = [kSHA512Check uppercaseString];
	XCTAssertEqualObjects(sha512String, sha512CHECK, @"" );
}

-(void)testSHA512OnNSData {
    NSString *sha512String = [self.json_data acm_sha512];
    XCTAssertEqualObjects( sha512String, kSHA512Check, @"" );
}

-(void)testSHA512OnNSString {
    NSString *sha512_string = [self.json_string acm_sha512];
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

static NSString * const kSignKey = @"qwertyazerty";

#pragma mark nil tests

-(void)testNilHMAC {
    NSString *hmac_one = [self.json_data acm_hmac:(kACMHMACAlgSHA1 - 1) key:kSignKey];
    XCTAssertNil( hmac_one, @"" );
    
    NSString *hmac_two = [self.json_data acm_hmac:(kACMHMACAlgSHA224 + 1) key:kSignKey];
    XCTAssertNil( hmac_two, @"" );
    
    NSString *hmac_three = [self.json_data acm_hmac:kACMHMACAlgMD5 key:nil];
    XCTAssertNil( hmac_three, @"" );
}


#pragma mark MD5

/*!
 *	@discussion
 *		Signature generated via Terminal:
 *			> openssl dgst -md5 -hmac "<kSignKey>" ACMECrypt/AMCEAssymTests/sample_large_json.json
 */

static NSString * const kJSONMD5Check = @"ddb67a34c3f54728ef3130fbf2031498";

-(void)testSignMD5Core {
	NSData *hmacedJSON = (__bridge id)ACMHmac(
                                              (__bridge CFDataRef)self.json_data,
                                              (__bridge CFStringRef)kSignKey,
                                              kACMHMACAlgMD5 );
	XCTAssertNotNil(hmacedJSON, @"" );
	XCTAssertTrue( hmacedJSON.length > 0, @"" );

	NSString *hexedJSON = (__bridge NSString *)ACMDataToHEX((__bridge CFDataRef)hmacedJSON,TRUE);
	XCTAssertEqualObjects(hexedJSON, [kJSONMD5Check uppercaseString], @"" );
	
	NSString *lowerHex = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)(hmacedJSON), FALSE);
	XCTAssertEqualObjects( lowerHex, kJSONMD5Check, @"" );
}

-(void)testSignMD5OnNSData {
    NSString *md5Sign = [self.json_data acm_hmacMD5:kSignKey];
    XCTAssertEqualObjects(md5Sign, kJSONMD5Check, @"" );
}

-(void)testSignMD5OnNSString {
    NSString *md5String = [self.json_string acm_hmacMD5:kSignKey];
    XCTAssertEqualObjects( md5String, kJSONMD5Check, @"" );
}

#pragma mark SHA1

/*!
 *	@discussion
 *		Signature generated via Terminal:
 *			> openssl dgst -sha1 -hmac "<kSignKey>" ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
static NSString * const kJSONSHA1Check = @"b82f69844a68cdc6daf8a4235d34ede793bfb274";

-(void)testSignHMACSHA1Core {
    NSData *hmacedJSON = (__bridge id)ACMHmac(
                                              (__bridge CFDataRef)self.json_data,
                                              (__bridge CFStringRef)kSignKey,
                                              kACMHMACAlgSHA1 );
    XCTAssertNotNil(hmacedJSON, @"" );
	XCTAssertTrue( hmacedJSON.length > 0, @"" );
    
	NSString *hexedJSON = (__bridge NSString *)ACMDataToHEX((__bridge CFDataRef)hmacedJSON,TRUE);
	XCTAssertEqualObjects(hexedJSON, [kJSONSHA1Check uppercaseString], @"" );
	
	NSString *lowerHex = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)(hmacedJSON), FALSE);
	XCTAssertEqualObjects( lowerHex, kJSONSHA1Check, @"" );
}

-(void)testSHA1SignOnNSData {
    NSString *sha1 = [self.json_data acm_hmacSHA1:kSignKey];
    XCTAssertEqualObjects( sha1, kJSONSHA1Check, @"" );
}

-(void)testSignSHA1OnNSString {
    NSString *sha1 = [self.json_string acm_hmacSHA1:kSignKey];
    XCTAssertEqualObjects( sha1, kJSONSHA1Check, @"" );
}

/**
 *  @discussion
 *      Again, from the TWitter example;
 *          https://dev.twitter.com/docs/auth/creating-signature
 */
static NSString * const kTwtrHMACSHA1Key = @"kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";
static NSString * const kTwtrSHA1Result = @"B679C0AF18F4E9C587AB8E200ACD4E48A93F8CB6";

-(void)testHMAC_SHA1_TwitterExample {
    NSString *twtrSHA1 = [kTwtrSignatureBaseString acm_hmacSHA1:kTwtrHMACSHA1Key];
    XCTAssertEqualObjects( twtrSHA1, [kTwtrSHA1Result lowercaseString] , @"" );
}

#pragma mark SHA224

/*!
 *	@discussion
 *		Signature generated via Terminal:
 *			> openssl dgst -sha224 -hmac "<kSIgnKey>" ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
static NSString * const kJSONSHA224Check = @"701a0b51bfa0efe0398ed17ac9c93969f8f6a9860e2135ff8438fba3";

-(void)testSingSHA224Core {
    NSData *hmacedJSON = (__bridge id)ACMHmac(
                                              (__bridge CFDataRef)self.json_data,
                                              (__bridge CFStringRef)kSignKey,
                                              kACMHMACAlgSHA224 );
    XCTAssertNotNil(hmacedJSON, @"" );
	XCTAssertTrue( hmacedJSON.length > 0, @"" );
    
	NSString *hexedJSON = (__bridge NSString *)ACMDataToHEX((__bridge CFDataRef)hmacedJSON,TRUE);
	XCTAssertEqualObjects(hexedJSON, [kJSONSHA224Check uppercaseString], @"" );
	
	NSString *lowerHex = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)(hmacedJSON), FALSE);
	XCTAssertEqualObjects( lowerHex, kJSONSHA224Check, @"" );
}

-(void)testSignSHA224OnNSData {
    NSString *sha224String = [self.json_data acm_hmacSHA224:kSignKey];
    XCTAssertEqualObjects( sha224String, kJSONSHA224Check, @"" );
}

-(void)testSignSHA224OnNSString {
    NSString *sha = [self.json_string acm_hmacSHA224:kSignKey];
    XCTAssertEqualObjects( sha, kJSONSHA224Check, @"" );
}

#pragma mark SHA256

/*!
 *	@discussion
 *		Signature generated via Terminal:
 *			> openssl dgst -sha256 -hmac "<kSignKey" ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
static NSString * const kJSONSHA256Check = @"249d925e85edfd266f9d23b3fae0498b2ef63edbdc5a897c181645f3b538bcd4";

-(void)testSignSHA256Core {
    NSData *hmacedJSON = (__bridge id)ACMHmac(
                                              (__bridge CFDataRef)self.json_data,
                                              (__bridge CFStringRef)kSignKey,
                                              kACMHMACAlgSHA256 );
    XCTAssertNotNil(hmacedJSON, @"" );
	XCTAssertTrue( hmacedJSON.length > 0, @"" );
    
	NSString *hexedJSON = (__bridge NSString *)ACMDataToHEX((__bridge CFDataRef)hmacedJSON,TRUE);
	XCTAssertEqualObjects(hexedJSON, [kJSONSHA256Check uppercaseString], @"" );
	
	NSString *lowerHex = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)(hmacedJSON), FALSE);
	XCTAssertEqualObjects( lowerHex, kJSONSHA256Check, @"" );
}

-(void)testSignSHA256OnNSData {
    NSString *sha256String = [self.json_data acm_hmacSHA256:kSignKey];
    XCTAssertEqualObjects( sha256String, kJSONSHA256Check, @"" );
}

-(void)testSignSHA256OnNSString {
    NSString *sha = [self.json_string acm_hmacSHA256:kSignKey];
    XCTAssertEqualObjects( sha, kJSONSHA256Check, @"" );
}

#pragma mark SHA384

/*!
 *	@discussion
 *		Signature generated via Terminal:
 *			> openssl dgst -sha384 -hmac "<kSignKey" ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
static NSString * const kJSONSHA384Check = @"af8b3cc7d170ece68aedeb09faa38098ec221254f5a7b6ae3fd27bc168b50f3ef44323a7cd49382cd21298c0a1385b75";

-(void)testSignSHA384Core {
    NSData *jsonData = self.json_data;
    NSData *hmacedJSON = (__bridge id)ACMHmac(
                                              (__bridge CFDataRef)jsonData,
                                              (__bridge CFStringRef)kSignKey,
                                              kACMHMACAlgSHA384 );
    XCTAssertNotNil(hmacedJSON, @"" );
	XCTAssertTrue( hmacedJSON.length > 0, @"" );
    
	NSString *hexedJSON = (__bridge NSString *)ACMDataToHEX((__bridge CFDataRef)hmacedJSON,TRUE);
	XCTAssertEqualObjects(hexedJSON, [kJSONSHA384Check uppercaseString], @"" );
	
	NSString *lowerHex = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)(hmacedJSON), FALSE);
	XCTAssertEqualObjects( lowerHex, kJSONSHA384Check, @"" );
}

-(void)testSignSHA384OnNSData {
    NSString *sha384String = [self.json_data acm_hmacSHA384:kSignKey];
    XCTAssertEqualObjects( sha384String, kJSONSHA384Check, @"" );
}

-(void)testSignSHA384OnNSString {
    NSString *sha = [self.json_string acm_hmacSHA384:kSignKey];
    XCTAssertEqualObjects( sha, kJSONSHA384Check, @"" );
}

#pragma mark SHA512

/*!
 *	@discussion
 *		Signature generated via Terminal:
 *			> openssl dgst -sha512 -hmac "<kSignKey" ACMECrypt/AMCEAssymTests/sample_large_json.json
 */
static NSString * const kJSONSHA512Check = @"fc2b9f75b813094674ef9ae8d9c8174515827b2bd8188d6280509172d6143ecb1ad4b201668800a4c75d1fc1be3ac9476c975e7cd146f749b024ebd11733c554";

-(void)testSignSHA512Core {
    NSData *jsonData = self.json_data;
    NSData *hmacedJSON = (__bridge id)ACMHmac(
                                              (__bridge CFDataRef)jsonData,
                                              (__bridge CFStringRef)kSignKey,
                                              kACMHMACAlgSHA512 );
    XCTAssertNotNil(hmacedJSON, @"" );
	XCTAssertTrue( hmacedJSON.length > 0, @"" );
    
	NSString *hexedJSON = (__bridge NSString *)ACMDataToHEX((__bridge CFDataRef)hmacedJSON,TRUE);
	XCTAssertEqualObjects(hexedJSON, [kJSONSHA512Check uppercaseString], @"" );
	
	NSString *lowerHex = (__bridge NSString*)ACMDataToHEX((__bridge CFDataRef)(hmacedJSON), FALSE);
	XCTAssertEqualObjects( lowerHex, kJSONSHA512Check, @"" );
}

-(void)testSignSHA512OnNSData {
    NSString *sha512String = [self.json_data acm_hmacSHA512:kSignKey];
    XCTAssertEqualObjects( sha512String, kJSONSHA512Check, @"" );
}

-(void)testSignSHA512OnNSString {
    NSString *sha = [self.json_string acm_hmacSHA512:kSignKey];
    XCTAssertEqualObjects( sha, kJSONSHA512Check, @"" );
}

@end
