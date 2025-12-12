#pragma once
#include <string>
#include <files.h>
#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <fstream>

#include "cryptlib.h"
#include "filters.h"
#include "files.h"
#include "modes.h"
#include "hex.h"
#include "aes.h"
#include "crc.h"

using namespace std;
using namespace CryptoPP;

inline void removeLineBreak(string& line) {
	line.erase(remove_if(line.begin(), line.end(), [](char c) { return c == '\n'; }), line.end());
}

class Crypt
{
public:
	Crypt() {

	}

	~Crypt() {

	}

	string publicKey() { return mPublicKey; }

	string privateKey() { return mPrivateKey; }

	void setPrivateKey(string privateKey) {
		mPrivateKey = privateKey;
	}

	string encodedAesKey() { return mEncodedAesKey; }

	void setEncodedAesKey(string encodedAesKey) { mEncodedAesKey = encodedAesKey; }

	string encryptAES(char* content, int contentSize) {
		byte key[AES::MIN_KEYLENGTH];
		byte iv[AES::BLOCKSIZE];
		vector<byte> plainVector, cipher;
		plainVector.assign(content, content + contentSize);

		string decodedAesKey;
		StringSource(mEncodedAesKey, true, new Base64Decoder(new StringSink(decodedAesKey)));

		memset(key, 0x00, sizeof(key));
		memcpy(key, decodedAesKey.c_str(), decodedAesKey.length());
		memset(iv, 0x00, sizeof(iv));

		CBC_Mode<AES>::Encryption encryption;
		encryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

		cipher.resize(contentSize + AES::BLOCKSIZE);
		ArraySink cs(&cipher[0], cipher.size());
		ArraySource(plainVector.data(), plainVector.size(), true, new StreamTransformationFilter(encryption, new Redirector(cs)));
		cipher.resize(cs.TotalPutLength());
		string encrypted(cipher.begin(), cipher.end());

		string result;
		StringSource(encrypted, true, new Base64Encoder(new StringSink(result)));
		return result;
	}

	void generateRSAKeyPair() {
		AutoSeededRandomPool randomPool;
		InvertibleRSAFunction privKey;
		privKey.Initialize(randomPool, 1024);

		Base64Encoder privKeySink(new StringSink(mPrivateKey));
		privKey.DEREncode(privKeySink);
		privKeySink.MessageEnd();
		removeLineBreak(mPrivateKey);

		RSAFunction pubKey(privKey);
		Base64Encoder pubKeySink(new StringSink(mPublicKey));
		pubKey.DEREncode(pubKeySink);
		pubKeySink.MessageEnd();
		removeLineBreak(mPublicKey);
	}

	string decryptRSA(string content) {
		AutoSeededRandomPool randomPool;
		ByteQueue byteQueue;
		StringSource ss1(mPrivateKey, true, new Base64Decoder);
		ss1.TransferTo(byteQueue);
		byteQueue.MessageEnd();

		RSA::PrivateKey privateKey;
		privateKey.Load(byteQueue);

		string decodedContent;
		StringSource ss2(content.c_str(), true, new Base64Decoder(new StringSink(decodedContent)));

		string result;
		RSAES_PKCS1v15_Decryptor rsaDecryptor(privateKey);
		StringSource ss3(decodedContent, true, new PK_DecryptorFilter(randomPool, rsaDecryptor, new StringSink(result)));
		return result;
	}
	
protected:
	string mPublicKey;
	string mPrivateKey;

	string mEncodedAesKey;
};

