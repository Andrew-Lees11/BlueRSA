//
//  CryptorRSATests.swift
//  CryptorRSA
//
//  Created by Bill Abt on 1/17/17.
//
//  Copyright © 2017 IBM. All rights reserved.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

import XCTest
//#if os(Linux)
    import OpenSSL
//#endif

@testable import CryptorRSA

@available(macOS 10.12, iOS 10.0, *)
class CryptorRSATests: XCTestCase {
	
	/// Test for bundle usage.
    static var useBundles: Bool {
        if let bundle = CryptorRSATests.bundle {
            let path = bundle.path(forResource: "public", ofType: "der")
            return path != nil
        } else {
            return false
        }
    }
    
    //#if os(Linux)
        static let bundle: Bundle? = nil
//    #else
//        static let bundle: Bundle? = Bundle(for: CryptorRSATests.self)
//    #endif
	
	///
	/// Platform independent utility function to locate test files.
	///
	/// - Parameters:
	///		- resource:			The name of the resource to find.
	///		- ofType:			The type (i.e. extension) of the resource.
	///
	///	- Returns:	URL for the resource or nil if a path to the resource cannot be found.
	///
    static public func getFilePath(for resource: String, ofType: String) -> URL? {
        
        var path: URL
        
        if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
            guard let bPath = bundle.path(forResource: resource, ofType: ofType) else {
                
                return nil
            }
            path = URL(fileURLWithPath: bPath)
            
        } else {
            
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/" + resource + "." + ofType).standardized
        }
        
        return path
    }

    
	// MARK: Public Key Tests
	
	func test_public_initWithData() throws {
		
        let path = CryptorRSATests.getFilePath(for: "public", ofType: "der")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let data = try Data(contentsOf: filePath)
            let publicKey = try? CryptorRSA.createPublicKey(with: data)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey!.type == .publicType)
        }
	}
	
    // Certificate is PEM
	func test_public_initWithCertData() throws {
		
		let path = CryptorRSATests.getFilePath(for: "staging", ofType: "cer")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let data = try Data(contentsOf: filePath)
            let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: data)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey!.type == .publicType)
        }
	}
	
    // Certificate is PEM
	func test_public_initWithCertData2() throws {
		
		let path = CryptorRSATests.getFilePath(for: "staging2", ofType: "cer")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let data = try Data(contentsOf: filePath)
            let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: data)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey!.type == .publicType)
        }
	}
	
    // Public key is base64 encoded DER
	func test_public_initWithBase64String() throws {
		
        let path = CryptorRSATests.getFilePath(for: "public-base64", ofType: "txt")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let str = try String(contentsOf: filePath, encoding: .utf8)
            let publicKey = try? CryptorRSA.createPublicKey(withBase64: str)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey!.type == .publicType)
        }
	}
	

	func test_public_initWithBase64StringWhichContainsNewLines() throws {
		
        let path = CryptorRSATests.getFilePath(for: "public-base64-newlines", ofType: "txt")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let str = try String(contentsOf: filePath, encoding: .utf8)
            let publicKey = try? CryptorRSA.createPublicKey(withBase64: str)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey!.type == .publicType)
        }
	}
	
	func test_public_initWithPEMString() throws {
		
        let path = CryptorRSATests.getFilePath(for: "public", ofType: "pem")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let str = try String(contentsOf: filePath, encoding: .utf8)
            let publicKey = try? CryptorRSA.createPublicKey(withPEM: str)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey!.type == .publicType)
        }
	}
	
	func test_public_initWithPEMName() throws {
		
		if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
			
			let publicKey = try? CryptorRSA.createPublicKey(withPEMNamed: "public", in: bundle)
			XCTAssertNotNil(publicKey)
		
		} else {
			
			let publicKey = try? CryptorRSA.createPublicKey(withPEMNamed: "public", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}
	}
	
	func test_public_initWithDERName() throws {
		
		if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
			
			let publicKey = try? CryptorRSA.createPublicKey(withDERNamed: "public", in: bundle)
			XCTAssertNotNil(publicKey)
			
		} else {
			
			let publicKey = try? CryptorRSA.createPublicKey(withDERNamed: "public", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}
		
	}

    // This function tests stripping a PEM string that's already been stripped...
//    func test_public_initWithPEMStringHeaderless() throws {
//
//        let path = CryptorRSATests.getFilePath(for: "public-headerless", ofType: "pem")
//        XCTAssertNotNil(path)
//
//        if let filePath = path {
//            let str = try String(contentsOf: filePath, encoding: .utf8)
//            let publicKey = try? CryptorRSA.createPublicKey(withPEM: str)
//            XCTAssertNotNil(publicKey)
//            XCTAssertTrue(publicKey!.type == .publicType)
//        }
//    }
	
//    func test_publicKeysFromComplexPEMFileWorksCorrectly() {
//
//        guard let input = CryptorRSATests.pemKeyString(name: "multiple-keys-testcase") else {
//            XCTFail()
//            return
//        }
//
//        let keys = CryptorRSA.PublicKey.publicKeys(withPEM: input)
//        XCTAssertEqual(keys.count, 9)
//
//        for publicKey in keys {
//            XCTAssertTrue(publicKey.type == .publicType)
//        }
//    }
	
	func test_publicKeysFromEmptyPEMFileReturnsEmptyArray() {
		
		let keys = CryptorRSA.PublicKey.publicKeys(withPEM: "")
		XCTAssertEqual(keys.count, 0)
	}
	

	func test_public_initWithCertificateName() throws {
		
		if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
			
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging", in: bundle)
			XCTAssertNotNil(publicKey)
			
		} else {
			
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}
		
	}
	
	func test_public_initWithCertificateName2() throws {
		
		if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
			
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging2", in: bundle)
			XCTAssertNotNil(publicKey)
			
		} else {
			
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging2", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}
		
	}
	
	// MARK: Private Key Tests
	
	func test_private_initWithPEMString() throws {
		
        let path = CryptorRSATests.getFilePath(for: "private", ofType: "pem")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let str = try String(contentsOf: filePath, encoding: .utf8)
            let privateKey = try? CryptorRSA.createPrivateKey(withPEM: str)
            XCTAssertNotNil(privateKey)
            XCTAssertTrue(privateKey!.type == .privateType)
        }
	}
	
	func test_private_initWithPEMStringHeaderless() throws {
		
        let path = CryptorRSATests.getFilePath(for: "private-headerless", ofType: "pem")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let str = try String(contentsOf: filePath, encoding: .utf8)
            let privateKey = try? CryptorRSA.createPrivateKey(withPEM: str)
            XCTAssertNotNil(privateKey)
            XCTAssertTrue(privateKey!.type == .privateType)
        }
	}
	
	func test_private_initWithPEMName() throws {
		
		if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
			
			let privateKey = try? CryptorRSA.createPrivateKey(withPEMNamed: "private", in: bundle)
			XCTAssertNotNil(privateKey)
			
		} else {
			
			let privateKey = try? CryptorRSA.createPrivateKey(withPEMNamed: "private", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(privateKey)
		}
		
	}
	
	func test_private_initWithDERName() throws {
		
		if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
			
			let privateKey = try? CryptorRSA.createPrivateKey(withDERNamed: "private", in: bundle)
			XCTAssertNotNil(privateKey)
			
		} else {
			
			let privateKey = try? CryptorRSA.createPrivateKey(withDERNamed: "private", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(privateKey)
		}
		
	}

	// MARK: Encyption/Decryption Tests
    
    let publicKey: CryptorRSA.PublicKey? = try? CryptorRSATests.publicKey(name: "public")
    let privateKey: CryptorRSA.PrivateKey? = try? CryptorRSATests.privateKey(name: "private")
	
	func test_simpleEncryption() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
		                                              (.sha224, ".sha224"),
		                                              (.sha256, ".sha256"),
		                                              (.sha384, ".sha384"),
		                                              /*(.sha512, ".sha512")*/]
		// Test all the algorithms available...
		//	Note: .sha512 encryption appears to be broken internally on Apple platforms, so we skip it...
		for (algorithm, name) in algorithms {
		
			print("Testing algorithm: \(name)")
			let str = "Plain Text"
			let plainText = try CryptorRSA.createPlaintext(with: str, using: .utf8)
            
            guard let publicKey = self.publicKey,
                  let privateKey = self.privateKey else {
                XCTFail("Could not find key")
                return
            }
            
			let encrypted = try plainText.encrypted(with: publicKey, algorithm: algorithm)
			XCTAssertNotNil(encrypted)
            print(encrypted!.base64String)
			let decrypted = try encrypted!.decrypted(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(decrypted)
            print(decrypted!.base64String)
			let decryptedString = try decrypted!.string(using: .utf8)
			XCTAssertEqual(decryptedString, str)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	func test_longStringEncryption() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
		                                              (.sha224, ".sha224"),
		                                              (.sha256, ".sha256"),
		                                              (.sha384, ".sha384"),
		                                              /*(.sha512, ".sha512")*/]
		// Test all the algorithms available...
		//	Note: .sha512 encryption appears to be broken internally on Apple platforms, so we skip it...
		for (algorithm, name) in algorithms {
			
			print("Testing algorithm: \(name)")
			let str = [String](repeating: "a", count: 9999).joined(separator: "")
			let plainText = try CryptorRSA.createPlaintext(with: str, using: .utf8)
		
            guard let publicKey = self.publicKey,
                let privateKey = self.privateKey else {
                    XCTFail("Could not find key")
                    return
            }
            
			let encrypted = try plainText.encrypted(with: publicKey, algorithm: algorithm)
			XCTAssertNotNil(encrypted)
			let decrypted = try encrypted!.decrypted(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(decrypted)
			let decryptedString = try decrypted!.string(using: .utf8)
			XCTAssertEqual(decryptedString, str)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	func test_randomByteEncryption() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
		                                              (.sha224, ".sha224"),
		                                              (.sha256, ".sha256"),
		                                              (.sha384, ".sha384"),
		                                              /*(.sha512, ".sha512")*/]
		// Test all the algorithms available...
		//	Note: .sha512 encryption appears to be broken internally on Apple platforms, so we skip it...
		for (algorithm, name) in algorithms {
			
			print("Testing algorithm: \(name)")
			let data = CryptorRSATests.randomData(count: 2048)
			let plainData = CryptorRSA.createPlaintext(with: data)
		
            guard let publicKey = self.publicKey,
                let privateKey = self.privateKey else {
                    XCTFail("Could not find key")
                    return
            }
            
			let encrypted = try plainData.encrypted(with: publicKey, algorithm: algorithm)
			XCTAssertNotNil(encrypted)
			let decrypted = try encrypted!.decrypted(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(decrypted)
			XCTAssertEqual(decrypted!.data, data)
			print("Test of algorithm: \(name) succeeded")
		}
	}
    
    func test_ExistingKey() throws {
        let encryptedString = "yDgwwJ9fwIpfGshFsgsi1Kr4I8827tuMc8N0yMXSAHX21kpF2+RqtCVZnlJuWwSIkBchI7pxFKUhNhke0RA/tw5nrF/eIREuGabLFWfJ4MhcKKOnkdJqp/J7/pMIU7+Gei3pgpZCcDdCjYWJV0p+Jq20TrS2UYrtDSA22EmPKt7WdKDu+jrurTX5QB7jdGDNOguAxfkkAJakuDH/Q1edx6+r1+Eww77oh0HQYbB6ZlNk8+4l"
        let key =
"""
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDpbnF5g5bt9mjweE5nZioLAPKIl31qj5/ht4i62gsEg/6R/GMB
IAhUEgfr9n3H0jIKRoI0BvVH6+fUB9pKoMUdRu3VsAF9ExkuhwazpE1uIfRbf2IJ
HIAz5zX3emUdymHaPZPucQUF7G/XmOMK86qKl8Zdd8Gl8cTFpRVMoSs4lwIDAQAB
AoGAcs/ZjDTGxWAPGUdy+LRtNWBP6hLoosLllnVZEN4x0RTC3zbN0z3YGtGLh+mC
0Ad4iUlIvSI2/hrvuX/rRA1zJRSWqmUi+K/IQtRqH4L29xfDT9yxVd5X61vb5dGs
nruBHBSdcfsLKrQZClAqGKNElVfLn5+vaf48hsm9de5lSRECQQD+WcQHRSEyuuWl
dW0qhfRBXjtqnvS1VQ+CmS4nzeAVfNLV8KzJvx/evoQ9KxbnwfN/fQkyniK0RzNs
kcXNZFsLAkEA6vHzWrQVtiQ5b8itwn3er7FWWy53SFLiy2MJCUBmm0Z2uJXox4Ym
nH2SoUVMHJOvqgdqcwz53RJIlMPkAMgwJQJAbYTDZon6qHhXR65PSh8RtE/Z76fw
IGA25HoGqLb6BOaRdfNCwz/bfjK0iA4Ut8gIi92P5062DMAXwWjnLfBHTwJBAM0E
p2xeO5f+0lQ2lVJkDj/Yi1f0G0j0c04yNL9rAF69RXpb7o62BNmIRr0OQJWrVp4T
7JNLHnsIqmeO7Va1WjUCQQDcY8s947hfiISXQ9o6auz33WyIRQWt/x0WdujVsxjM
JNHkkGxCfEjy9Z74EO8MoSddiM4+u7gPZsr5f6AZvMsj
-----END RSA PRIVATE KEY-----
"""
        print("Testing algorithm: \(name)")
        guard let privateKey = try? CryptorRSA.createPrivateKey(withPEM: key) else {
                XCTFail("Could not find key")
                return
        }
        let encrypted = try CryptorRSA.createEncrypted(with: encryptedString)
        let decrypted = try encrypted.decrypted(with: privateKey, algorithm: .sha256)
        XCTAssertNotNil(decrypted)
        let decryptedString = try decrypted!.string(using: .utf8)
        print(decryptedString)
        print("Test of algorithm: \(name) succeeded")
    }
	
    func test_DataDecryption() throws {
        let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
                                                      (.sha224, ".sha224"),
                                                      (.sha256, ".sha256"),
                                                      (.sha384, ".sha384"),
                                                      /*(.sha512, ".sha512")*/]
        // Test all the algorithms available...
        //    Note: .sha512 encryption appears to be broken internally on Apple platforms, so we skip it...
        for (algorithm, name) in algorithms {
        
        print("Testing algorithm: \(name)")
        let str = "Plain Text"
        let plainText = try CryptorRSA.createPlaintext(with: str, using: .utf8)
        
        guard let publicKey = self.publicKey,
        let privateKey = self.privateKey else {
        XCTFail("Could not find key")
        return
        }
        
        guard let plaintextEncrypted = try plainText.encrypted(with: publicKey, algorithm: algorithm) else {
        return XCTFail("Failed to encrypt plaintext")
        }
        let encryptedString = plaintextEncrypted.base64String
        let encrypted = try CryptorRSA.createEncrypted(with: encryptedString)
        let decrypted = try encrypted.decrypted(with: privateKey, algorithm: algorithm)
        XCTAssertNotNil(decrypted)
        let decryptedString = try decrypted!.string(using: .utf8)
        XCTAssertEqual(decryptedString, str)
        print("Test of algorithm: \(name) succeeded")
        }
    }

	// MARK: Signing/Verification Tests
	
	func test_signVerifyAllDigestTypes() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
		                                              (.sha224, ".sha224"),
		                                              (.sha256, ".sha256"),
		                                              (.sha384, ".sha384"),
		                                              (.sha512, ".sha512")]
        guard let publicKey = self.publicKey,
            let privateKey = self.privateKey else {
                XCTFail("Could not find key")
                return
        }
        
		// Test all the algorithms available...
		for (algorithm, name) in algorithms {
			
			print("Testing algorithm: \(name)")
			let data = CryptorRSATests.randomData(count: 8192)
			let message = CryptorRSA.createPlaintext(with: data)
			let signature = try message.signed(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(signature)
			let verificationResult = try message.verify(with: publicKey, signature: signature!, algorithm: algorithm)
			XCTAssertTrue(verificationResult)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	func test_signVerifyBase64() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
		                                              (.sha224, ".sha224"),
		                                              (.sha256, ".sha256"),
		                                              (.sha384, ".sha384"),
		                                              (.sha512, ".sha512")]
        
        guard let publicKey = self.publicKey,
            let privateKey = self.privateKey else {
                XCTFail("Could not find key")
                return
        }
        
		// Test all the algorithms available...
		for (algorithm, name) in algorithms {
			
			print("Testing algorithm: \(name)")
			let data = CryptorRSATests.randomData(count: 8192)
			let message = CryptorRSA.createPlaintext(with: data)
			let signature = try message.signed(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(signature)
			XCTAssertEqual(signature!.base64String, signature!.data.base64EncodedString())
			let verificationResult = try message.verify(with: publicKey, signature: signature!, algorithm: algorithm)
			XCTAssertTrue(verificationResult)
			print("Test of algorithm: \(name) succeeded")
		}
	}
    
    func test_signFirebase() throws {
        
        let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
                                                      (.sha224, ".sha224"),
                                                      (.sha256, ".sha256"),
                                                      (.sha384, ".sha384"),
                                                      (.sha512, ".sha512")]
        
        let privateKeyString = """
-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDxGWG6vFwmfenW\n8jWTd6vzofsKdRWynJut57/qBQyarS9fziLCUwZpfxxc9kCtbM0erugdzw9mnPSs\n//YC4dh20za6y9i1fLwTUZB9n6eaQvi2B5cJ/hOECLqTtUXQl8fb+7TIg7rmcp2o\n8uE1XOel6hyJXRr3IJnwOeMet3SsSfJq8emz13hCpW7jOLwyOX5GOjbpojGE+U44\n0N67HVMzqqIkk3KSOrdHQbuWxWvaENumsNDpUEzUTqZqerdYSC/F6aXgwytza0Vx\nXqMgoMHq2u76UFrjQ+Vvu3724KyktTwjf71r1UhLiOt3AP1ILVN9vfY1QpZXkcHK\nTAKZLTeTAgMBAAECggEAC8/lXgY7cjaqCGS5I5Px4eUA4nbGYjKnspdPljy6wjCT\nnnCAJcrL3iBNo0T8pI0s5tYakNdOVwXVO6KWCsxw1AWDbBcaSMNR3ZUZ7KWv9Zqs\nCmhdydi1BmYnv0kwIJ5HEEEz5BJcIPfi6d5DErUOCQQVc39obPd1GJ66wLcBPtg6\nRxgovLrSSn1ZcInto0aUUI/J/raMTrkryMnF4BwjrWREAvFf8kBhordtZzI2CcJP\nmm02nLf+PgX+hFKIewKScsusFHujHBhUn5z2eZl5QWHxxizLUnoWab7P9Ztlo4Oq\nO8h/1UX3LWiCZhKHNQyos9qZfn0mGgZOxs4WPWr+2QKBgQD5CXsyu0eAGMu2JCMM\nvZ2SEe6vjhR0/AFjhTTzMr3SXjkUXAhfnlzJNJ0O4vhSXGepjq7eFRW1tRAXp5CN\nfatwzqZ9Ai6YUZiC7zRp33BjZFpd/RBZgqoJFczUjVGJtYTOmZETgEpWUUGtUTk0\nKT+WDT3zvvS+PW03k2FtZqny2wKBgQD31xV76cEl3Sb484taVzYS1eZOkCU/oSep\nReVaCN7E+VOfd4G27xwx44SMEdIGL25hD/uX9/4hptisNa6iVgDxgxKdK4QQLvvG\n27VORZdrLJBkwZENHazAlCTTcJ0Hnt0M4izHCilwc/HeA16SoeVf9HSv0JmsbDtp\nZYeKiig/qQKBgFVQ/jffGRu1YvS/ZJKU00qbgh36mt+JBiDGHeHDXGyZgwyKiwPX\nCQqVT8kt0MzGg2z/SMEkkA90PFMeQNN4XieDZF4nRTdBnPIeaOJsfeBPHPZeIB/K\nN95s7YNT9r8qxJjS23TG2rC/nbR2wxYvm20YlETRAp+6A5SqlRIZvddJAoGBAO/Z\ndzE0R3gdTlofV/1V6T7RQtFFLsclbvyiaBN6Ah0eLY9mWGJxhRfC18O2e0sBHBFT\nJmkr1wU6MvZ1/Uudb8xKzPjN5EDFN2R7vDrDnoZZ2mOn8HiA/25f8EOv+EgntkWB\nnVQCwZfSnX/+QsglZZY3PbXoatAy7kxRtZqdmdYBAoGALTxCnbz6G34Xtqy6d1PR\nqiSzn7kYP3vasfHZqrvhJ99cvK4VNxlp/zJCqb0GBxT/ZdAItLp94VueiS3hubNS\n5pxOfbUPKxzxWK5xzmmxWm/0bUT55A1fW6IRlKSdRuQH1pMb+jYZRmUa9Y1DV8ey\npgSl+MBViZj8bRuCJ9SkuuA=\n-----END PRIVATE KEY-----\n
"""
        
        // Test all the algorithms available...
        for (algorithm, name) in algorithms {
            
            print("Testing algorithm: \(name)")
            let data = CryptorRSATests.randomData(count: 8192)
            let message = CryptorRSA.createPlaintext(with: data)
            if let privateKey = try? CryptorRSA.createPrivateKey(withPEM: privateKeyString) {
                let signature = try message.signed(with: privateKey, algorithm: algorithm)
                XCTAssertNotNil(signature)
                XCTAssertEqual(signature!.base64String, signature!.data.base64EncodedString())
                print("Test of algorithm: \(name) succeeded")
            }
        }
    }

    func test_verifyAppIDToken() throws {
        
        let certificatePEM = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn4Tw7golPpKj+VSQIiRT
            RApbtCMyn28btLu9nHQzf32J1niY/uJZZbo5O+MsekNPHu5qmLBFCS0M3HcYeKAk
            OZtu7z9W1Lkronpt7WBWu+7qnGZm2vPw9rOUflZjGS5Qh9RinPJ9S5tnOrO5VapA
            7Rb2Q6EU3scgsDFvVaxBERf6IuDXgwYZp+tCcmBccEDBIfQ44mvu/6dHPwAUICJw
            3y/S4hqv2VEDslEdAJm2kj+WRIYooFBPVlp7371iVZtmV9cStBLW5igBvePe5ots
            lU7tI2NCoSxFONjF+kGxO2S8mbBzADTBXaAE7clHorp6nRj8rIxHzD0V3+W8mp2W
            1QIDAQAB
            -----END PUBLIC KEY-----
            """
        
        guard let tokenPublicKey = try? CryptorRSA.createPublicKey(withPEM: certificatePEM) else {
            XCTFail("Public ket not made")
            return
        }

        XCTAssertTrue(tokenPublicKey.type == .publicType)
        
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC0xNTA0Njg1OTYxMDAwIn0.eyJpc3MiOiJhcHBpZC1vYXV0aC5uZy5ibHVlbWl4Lm5ldCIsImF1ZCI6IjUzOGU4NTI2YTcwNDdjMWM5ZTEzNDZhYzQ1MjA2NmQxYmE1ZmQzNTEiLCJleHAiOjE1MTgxOTkzNTgsInRlbmFudCI6ImQ3YmMzMjJjLWIyMjQtNDFjMS05MWVhLWZjNjM4YWUyYWQ0ZCIsImlhdCI6MTUxODE5NTc1OCwiZW1haWwiOiJhYXJvbi5saWJlcmF0b3JlQGdtYWlsLmNvbSIsIm5hbWUiOiJBYXJvbiBMaWJlcmF0b3JlIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS8tWGRVSXFkTWtDV0EvQUFBQUFBQUFBQUkvQUFBQUFBQUFBQUEvNDI1MnJzY2J2NU0vcGhvdG8uanBnIiwic3ViIjoiNGZiOTY0NDUtMGIzYy00Mzg2LWI3MmEtNTk2YmIzYTlkNDUwIiwiaWRlbnRpdGllcyI6W3sicHJvdmlkZXIiOiJnb29nbGUiLCJpZCI6IjEwODQ2MDkwMTMxMTMxNzgyOTg4NCJ9XSwiYW1yIjpbImdvb2dsZSJdLCJvYXV0aF9jbGllbnQiOnsibmFtZSI6IldhdHNvbiBUb25lIEFuYWx5emVyIFJLQUpHIiwidHlwZSI6Im1vYmlsZWFwcCIsInNvZnR3YXJlX2lkIjoiY29tLmlibS5XYXRzb25Ub25lQW5hbHl6ZXJSS0FKRyIsInNvZnR3YXJlX3ZlcnNpb24iOiIxLjAiLCJkZXZpY2VfaWQiOiI3QTk2QjJDQi1DNkI4LTRCNTYtQjA0Ri1FMTMwQjZDMkUxMUMiLCJkZXZpY2VfbW9kZWwiOiJpUGhvbmUiLCJkZXZpY2Vfb3MiOiJpT1MiLCJkZXZpY2Vfb3NfdmVyc2lvbiI6IjExLjIifX0.RTK5wV0b0mtbRayKg9IdGCnGXoA7bn4Gdx-YIQjaaELWJwpla2x1R1hMvL5It-MKMt_pyejzkdoTKR3v_VF4IMwnBWz83d0u6TVs28TbrgHAkXy6sAypIfEKc4gLOSHXkUBYREH2pbJSguxZNTwqKe_PKRSYtG0QrtffPUsESfnGkdfHdUsSigMjX5s5En8fLCGiNSQF2uyYREDFE6T0w5P3W5MR_Scloyhik1q7nv91PzlJ6Rn9_0F12zjzvPMTt7bobTdokaFVPcqjFWHJc4YCw-bzdBCxtzHxf3oVXeJzCzPNb_nOehZu-u7ue54NbYwcoZ_bokmsjCnQbFE_QA"
        
        let tokenParts = token.split(separator: ".")
        // JWT token should have 3 parts
        XCTAssertTrue(tokenParts.count == 3)
        
        // Signed message is the first two components of the token
        let messageData = (String(tokenParts[0] + "." + tokenParts[1]).data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue))!)
        XCTAssertNotNil(messageData)
        
        // signature is 3rd component
        let sigStr = String(tokenParts[2])
        // JWT gets rid of any base64 padding, so add padding to allow for proper decoding
        var sig = sigStr.padding(toLength: ((sigStr.count+3)/4)*4, withPad: "=", startingAt: 0)
        
        // JWT also does base64url encoding, so make the proper replacements so its proper base64 encoding
        sig = sig.replacingOccurrences(of: "-", with: "+")
        sig = sig.replacingOccurrences(of: "_", with: "/")
        
        guard let sigData = Data(base64Encoded: sig) else {
            XCTFail("Unable to create Signature Data")
            return
        }
        
        let message = CryptorRSA.createPlaintext(with: messageData)
        XCTAssertNotNil(message)
        
        let signature = CryptorRSA.createSigned(with: sigData)
        XCTAssertNotNil(signature)
        
        let verificationResult = try message.verify(with: tokenPublicKey, signature: signature, algorithm: .sha256)
        XCTAssertTrue(verificationResult)
    }
    
//    func test_ECDSA() {
//        let p8PrivateKey = """
//-----BEGIN PRIVATE KEY-----
//MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgGH2MylyZjjRdauTk
//xxXW6p8VSHqIeVRRKSJPg1xn6+KgCgYIKoZIzj0DAQehRANCAAS/mNzQ7aBbIBr3
//DiHiJGIDEzi6+q3mmyhH6ZWQWFdFei2qgdyM1V6qtRPVq+yHBNSBebbR4noE/IYO
//hMdWYrKn
//-----END PRIVATE KEY-----
//"""
//        let PemPrivateKey = """
//-----BEGIN EC PRIVATE KEY-----
//MHcCAQEEIJX+87WJ7Gh19sohyZnhxZeXYNOcuGv4Q+8MLge4UkaZoAoGCCqGSM49
//AwEHoUQDQgAEikc5m6C2xtDWeeAeT18WElO37zvFOz8p4kAlhvgIHN23XIClNESg
//KVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
//-----END EC PRIVATE KEY-----
//"""
//        let publicKey = """
//-----BEGIN PUBLIC KEY-----
//MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEikc5m6C2xtDWeeAeT18WElO37zvF
//Oz8p4kAlhvgIHN23XIClNESgKVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
//-----END PUBLIC KEY-----
//"""
//
//        let exampleData = "Example".data(using: .utf8)!
//        guard let pemKey = CryptorECDSA.PrivateKey(pemKey: PemPrivateKey) else {
//            return XCTFail()
//        }
//        guard let ecdsaPublicKey = CryptorECDSA.PublicKey(pemKey: publicKey) else {
//            return XCTFail()
//        }
//        let eckey = EC_KEY_new_by_curve_name(NID_secp256k1)
//        EC_KEY_generate_key(eckey)
//        let ecpub = CryptorECDSA.PublicKey(nativeKey: eckey)
//        let ecpri = CryptorECDSA.PrivateKey(nativeKey: eckey)
//        guard let signature = CryptorECDSA.createSignature(data: exampleData, privateKey: ecpri) else {
//            return XCTFail()
//        }
//        let verified = CryptorECDSA.verifySignature(digestData: exampleData, signatureData: signature, publicKey: ecpub)
//        //let verified = CryptorECDSA.signAndVerify(data: exampleData, publicKey: ecdsaPublicKey, privateKey: pemKey)
//        XCTAssert(verified == true)
//    }
    
    func test_ECDSA() {
        let PemPrivateKey = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJX+87WJ7Gh19sohyZnhxZeXYNOcuGv4Q+8MLge4UkaZoAoGCCqGSM49
AwEHoUQDQgAEikc5m6C2xtDWeeAeT18WElO37zvFOz8p4kAlhvgIHN23XIClNESg
KVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
-----END EC PRIVATE KEY-----
"""
        let publicKey = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEikc5m6C2xtDWeeAeT18WElO37zvF
Oz8p4kAlhvgIHN23XIClNESgKVmLgSSq2asqiwdrU5YHbcHFkgdABM1SPA==
-----END PUBLIC KEY-----
"""
//        let eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)
//        EC_KEY_generate_key(eckey)
//
//        let ecpub = CryptorECDSA.PublicKey(nativeKey: eckey)
//        let ecpri = CryptorECDSA.PrivateKey(nativeKey: eckey)
//        let exampleData = "Example".data(using: .utf8)!
        let exampleJWTHeader = try! JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": "JWT"])
        let exampleJWTClaims = try! JSONSerialization.data(withJSONObject: ["sub": "1234567890","admin": true, "iat": 1516239022])
        
        let unsignedJWT = exampleJWTHeader.base64urlEncodedString() + "." + exampleJWTClaims.base64urlEncodedString()
        let unsignedData = unsignedJWT.data(using: .utf8)!
        
        guard let ecdsaPrivateKey = CryptorECDSA.PrivateKey(pemKey: PemPrivateKey) else {
            return XCTFail()
        }
        guard let ecdsaPublicKey = CryptorECDSA.PublicKey(pemKey: publicKey) else {
            return XCTFail()
        }
        guard let jwtSignature = CryptorECDSA.createSignature(data: unsignedData, privateKey: ecdsaPrivateKey) else {
            return XCTFail()
        }
        print(jwtSignature.base64urlEncodedString())
        print(unsignedJWT + "." + jwtSignature.base64urlEncodedString())
        let verified = CryptorECDSA.verifySignature(digestData: unsignedData, signatureData: jwtSignature, publicKey: ecdsaPublicKey)
        XCTAssert(verified == true)
    }

	// MARK: Test Utilities
	
	struct TestError: Error {
		let description: String
	}
	
	static public func pemKeyString(name: String) -> String? {
		
        guard let path = CryptorRSATests.getFilePath(for: name, ofType: "pem") else {
            XCTFail("Could not create pemKeyString")
            return nil
        }
        
        XCTAssertNotNil(path)
        
        guard let returnValue: String = try? String(contentsOfFile: path.path, encoding: String.Encoding.utf8) else {
            XCTFail("Could not create returnValue")
            return nil
        }
        
        XCTAssertNotNil(returnValue)
        
        return returnValue
	}
	
	static public func derKeyData(name: String) -> Data? {
		
        guard let path = CryptorRSATests.getFilePath(for: name, ofType: "der") else {
            XCTFail("Could not get file path")
            return nil
        }
        
        guard let returnValue: Data = try? Data(contentsOf: URL(fileURLWithPath: path.path)) else {
            XCTFail("Could not create derKeyData")
            return nil
        }
        
        return returnValue
	}
    
    enum MyError : Error {
        case invalidPath()
    }
	
	static public func publicKey(name: String) throws -> CryptorRSA.PublicKey {
		
        guard let path = CryptorRSATests.getFilePath(for: name, ofType: "pem") else {
            throw MyError.invalidPath()
        }
        
        let pemString = try String(contentsOf: path, encoding: String.Encoding.ascii)
        return try CryptorRSA.createPublicKey(withPEM: pemString)
	}
	
	static public func privateKey(name: String) throws -> CryptorRSA.PrivateKey {
		
        guard let path = CryptorRSATests.getFilePath(for: name, ofType: "pem") else {
            throw MyError.invalidPath()
        }
        
        let pemString = try String(contentsOf: path, encoding: String.Encoding.ascii)
        return try CryptorRSA.createPrivateKey(withPEM: pemString)
	}
	
	static public func randomData(count: Int) -> Data {
		
		var data = Data(count: count)
		data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) -> Void in
			
            //#if os(Linux)
                _ = RAND_bytes(bytes, Int32(count))
//            #else
//                _ = SecRandomCopyBytes(kSecRandomDefault, count, bytes)
//            #endif
		}
		return data
	}
	
	// MARK: Test Lists for Linux
	
	static var allTests : [(String, (CryptorRSATests) -> () throws -> Void)] {
        return [
            ("test_public_initWithData", test_public_initWithData),
            ("test_public_initWithCertData", test_public_initWithCertData),
            ("test_public_initWithCertData2", test_public_initWithCertData2),
            ("test_public_initWithBase64String", test_public_initWithBase64String),
            ("test_public_initWithBase64StringWhichContainsNewLines", test_public_initWithBase64StringWhichContainsNewLines),
            ("test_public_initWithPEMString", test_public_initWithPEMString),
            ("test_public_initWithPEMName", test_public_initWithPEMName),
            ("test_public_initWithDERName", test_public_initWithDERName),
//			("test_public_initWithPEMStringHeaderless", test_public_initWithPEMStringHeaderless),
//			("test_publicKeysFromComplexPEMFileWorksCorrectly", test_publicKeysFromComplexPEMFileWorksCorrectly),
            ("test_publicKeysFromEmptyPEMFileReturnsEmptyArray", test_publicKeysFromEmptyPEMFileReturnsEmptyArray),
            ("test_public_initWithCertificateName", test_public_initWithCertificateName),
            ("test_public_initWithCertificateName2", test_public_initWithCertificateName2),
            ("test_private_initWithPEMString", test_private_initWithPEMString),

//			("test_private_initWithPEMStringHeaderless", test_private_initWithPEMStringHeaderless),
            ("test_private_initWithPEMName", test_private_initWithPEMName),
            ("test_private_initWithDERName", test_private_initWithDERName),
            ("test_simpleEncryption", test_simpleEncryption),
            ("test_longStringEncryption", test_longStringEncryption),
            ("test_randomByteEncryption", test_randomByteEncryption),
			("test_signVerifyAllDigestTypes", test_signVerifyAllDigestTypes),
			("test_signVerifyBase64", test_signVerifyBase64),
            ("test_verifyAppIDToken", test_verifyAppIDToken),
        ]
    }
}

extension Data {
    func base64urlEncodedString() -> String {
        let result = self.base64EncodedString()
        return result.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
    init?(base64urlEncoded: String) {
        let paddingLength = 4 - base64urlEncoded.count % 4
        let padding = (paddingLength < 4) ? String(repeating: "=", count: paddingLength) : ""
        let base64EncodedString = base64urlEncoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + padding
        self.init(base64Encoded: base64EncodedString)
    }
}
