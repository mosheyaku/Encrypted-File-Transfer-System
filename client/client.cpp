#include <iostream>
#include <fstream>
#include <string>
#include <files.h>
#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <fstream>
#include <iomanip>

#include "cryptlib.h"
#include "filters.h"
#include "files.h"
#include "modes.h"
#include "hex.h"
#include "aes.h"
#include "crc.h"

#include "constants.h"
#include "client.h"

#pragma comment (lib, "Ws2_32.lib")

using namespace std;
using namespace CryptoPP;

inline void showLog(string header, string content) {
	cout << "[" + header + "] : " << content << endl;
}

Client::Client()
{
	mServerPort = 0;
	mRegistered = false;
	mSocket = NULL;
	mClientID = "";
}

Client::~Client()
{
	if (shutdown(mSocket, SD_BOTH) == SOCKET_ERROR) {
		closesocket(mSocket);
		WSACleanup();
	}
}

void Client::sendRequest(Request request)
{
	int headerLen = (int)sizeof(RequestHeader) + 1;
	char* headerBuf = new char[headerLen + 1];
	memcpy(headerBuf, (char*)&request.header, sizeof(RequestHeader));

	send(mSocket, headerBuf, headerLen, SOCK_STREAM);
	if (request.header.payload_size != 0 && request.payload != NULL)
		send(mSocket, request.payload, request.header.payload_size + 1, SOCK_STREAM);

	delete[] headerBuf;
}

void Client::receiveRespond(Respond& respond)
{
	recv(mSocket, (char*)&respond.header, sizeof(RespondHeader), 0);
	if (respond.header.payload_size != 0) {
		respond.payload = new char[respond.header.payload_size + 1];
		memset(respond.payload, 0, respond.header.payload_size + 1);
		recv(mSocket, respond.payload, respond.header.payload_size, 0);
	}
}

bool Client::readSetting()
{
	string line;
	// load transfer.info
	ifstream transferInfoFile(TRANSFER_FILE);
	if (!transferInfoFile.is_open())
		return false;

	if (!getline(transferInfoFile, line)) 
		return false;
	size_t pos = line.find_first_of(":");
	mServerIP = line.substr(0, pos);
	mServerPort = stoi(line.substr(pos + 1, -1));

	if (!getline(transferInfoFile, mClientName))
		return false;
	if (!getline(transferInfoFile, mTransferFileName)) 
		return false;

	// load me.info 
	mRegistered = false;
	ifstream meInfoFile(ME_FILE);
	if (meInfoFile.is_open()) {
		do {
			if (!getline(meInfoFile, mClientName))  
				break;
			if (!getline(meInfoFile, mClientID)) 
				break;
			mRegistered = true;
		} while (0);
	}
	// load priv.key
	if (mRegistered) {
		string privateKey;
		ifstream privKeyFile(PRIVATE_KEY_FILE);
		if (privKeyFile.is_open()) {
			if (!getline(privKeyFile, privateKey))
				return false;
			else {
				mCrypt.setPrivateKey(privateKey);
				return true;
			}
		}
		else
			return false;
	}
	return true;
}

char* Client::buildRequestNamePayload(uint32_t& payloadSize)
{
	payloadSize = 255;
	char* payload = new char[payloadSize + 1];
	memset(payload, 0, payloadSize + 1);
	memcpy(payload, mClientName.c_str(), mClientName.length());
	return payload;
}

char* Client::buildRequestFileNamePayload(uint32_t& payloadSize)
{
	payloadSize = 255;
	char* payload = new char[payloadSize + 1];
	memset(payload, 0, payloadSize + 1);
	memcpy(payload, mTransferFileName.c_str(), mTransferFileName.length());
	return payload;
}

char* Client::buildRequestShareKeyPayload(uint32_t& payloadSize)
{
	payloadSize = (uint32_t)(255 + mCrypt.publicKey().length());
	char* payload = new char[payloadSize + 1];
	memset(payload, 0, payloadSize + 1);
	memcpy(payload, mClientName.c_str(), mClientName.length());
	memcpy(&payload[255], mCrypt.publicKey().c_str(), mCrypt.publicKey().length());

	return payload;
}

char* Client::buildRequestSendFilePayload(uint32_t& payloadSize)
{
	// read transfer file
	ifstream transferFile(mTransferFileName, ios::out | ios::binary);
	transferFile.seekg(0, ios::end);
	size_t fileSize = transferFile.tellg();
	transferFile.seekg(0, ios::beg);

	char* fileContents = new char[fileSize + 1];
	memset(fileContents, 0, fileSize + 1);
	transferFile.read(fileContents, fileSize);

	// encrypt file content
	string encryptedContent = mCrypt.encryptAES(fileContents, (int)fileSize);
	delete[] fileContents;

	// build payload
	uint32_t encryptedContentSize = (uint32_t)encryptedContent.size();
	payloadSize = 4 + 255 + encryptedContentSize;

	char* payload = new char[payloadSize + 1];
	memset(payload, 0, payloadSize + 1);
	memcpy(payload, &fileSize, 4);
	memcpy(&payload[4], mTransferFileName.c_str(), mTransferFileName.size());
	memcpy(&payload[259], encryptedContent.c_str(), encryptedContentSize);

	return payload;
}

RespondClientIDPayload Client::parseClientIDPayload(char* payload, uint32_t payloadSize)
{
	RespondClientIDPayload respPayload;
	respPayload.mClientID = string(payload);
	return respPayload;
}

RespondShareKeyPayload Client::parseShareKeyPayload(char* payload, uint32_t payloadSize)
{
	RespondShareKeyPayload respPayload;
	respPayload.mClientID = string(payload).substr(0, 16);
	respPayload.mEncodedAesKey = mCrypt.decryptRSA(string(payload).substr(16, payloadSize - 16));
	return respPayload;
}

RespondFileAcceptPayload Client::parseFileAcceptPayload(char* payload, uint32_t payloadSize)
{
	RespondFileAcceptPayload respPayload;
	respPayload.mClientID = string(payload).substr(0, 16);
	memcpy(&respPayload.mContentSize, &payload[16], 4);
	respPayload.mTransferFileName = string(&payload[20]).substr(0, 255);
	int checkSum;
	memcpy(&checkSum, &payload[275], 4);
	stringstream stream;
	stream << hex << setw(8) << setfill('0') << checkSum;
	respPayload.mCheckSumHex = stream.str();
	return respPayload;
}

bool Client::connectToServer()
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		return false;
	}

	SOCKADDR_IN address{};
	int addrLen = sizeof(address);

	inet_pton(AF_INET, mServerIP.c_str(), &(address.sin_addr));
	address.sin_port = htons((u_short)mServerPort);
	address.sin_family = AF_INET;

	mSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connect(mSocket, (SOCKADDR*)&address, addrLen) == 0) {
		showLog("CONNECTION", "Success.");
		return true;
	}
	else {
		showLog("CONNECTION", "Fail.");
		closesocket(mSocket);
		WSACleanup();
		return false;
	}
}

bool Client::reigster()
{
	// send request
	Request request{};
	memcpy(request.header.client_id, mClientID.c_str(), 16);
	request.header.version = CLIENT_VERSION;
	request.header.code = REQUEST_REGISTER;
	request.payload = buildRequestNamePayload(request.header.payload_size);
	sendRequest(request);
	delete[] request.payload;

	// receive respond
	Respond respond{};
	receiveRespond(respond);
	if (respond.header.code != RESPOND_REGISTER_SUCCESS || respond.payload == NULL) {
		if (respond.payload != NULL)
			delete[] respond.payload;
		showLog("REGISTER", "Fail.");
		return false;
	}
	
	// parse payload
	RespondClientIDPayload respPayload = parseClientIDPayload(respond.payload, respond.header.payload_size);
	delete[] respond.payload;
	mClientID = respPayload.mClientID;
	
	// generate rsa key pair
	mCrypt.generateRSAKeyPair();
	
	// save me.info
	ofstream meInfoFile(ME_FILE);
	meInfoFile << mClientName << endl << mClientID << endl;
	meInfoFile.close();
	
	// save priv.key
	ofstream privKeyFile(PRIVATE_KEY_FILE);
	privKeyFile << mCrypt.privateKey() << endl;
	privKeyFile.close();

	showLog("REGISTER", "Success.");
	return true;
}

bool Client::shareKey()
{
	// send request
	Request request{};
	memcpy(request.header.client_id, mClientID.c_str(), 16);
	request.header.version = CLIENT_VERSION;
	request.header.code = REQUEST_SENDING_PUBKEY;
	request.payload = buildRequestShareKeyPayload(request.header.payload_size);
	sendRequest(request);
	delete[] request.payload;

	// receive respond
	Respond respond{};
	receiveRespond(respond);
	if (respond.header.code != RESPOND_SENDING_ENCKEY || respond.payload == NULL) {
		if (respond.payload != NULL)
			delete[] respond.payload;
		showLog("SHARE KEY", "Fail.");
		return false;
	}
	// parse payload
	RespondShareKeyPayload respPayload = parseShareKeyPayload(respond.payload, respond.header.payload_size);
	delete[] respond.payload;
	// set aes key 
	mCrypt.setEncodedAesKey(respPayload.mEncodedAesKey);
	showLog("SHARE KEY", "Success.");
	return true;
}

bool Client::login()
{
	// send request
	Request request{};
	memcpy(request.header.client_id, mClientID.c_str(), 16);
	request.header.version = CLIENT_VERSION;
	request.header.code = REQUEST_LOGIN;
	request.payload = buildRequestNamePayload(request.header.payload_size);
	sendRequest(request);
	delete[] request.payload;
	// receive respond
	Respond respond{};
	receiveRespond(respond);
	if (respond.header.code != RESPOND_LOGIN_CONFIRMED || respond.payload == NULL) {
		if (respond.payload != NULL)
			delete[] respond.payload;
		showLog("LOGIN", "Fail.");
		return false;
	}
	// parse payload
	RespondShareKeyPayload respPayload = parseShareKeyPayload(respond.payload, respond.header.payload_size);
	delete[] respond.payload;
	// set aes key 
	mCrypt.setEncodedAesKey(respPayload.mEncodedAesKey);
	showLog("LOGIN", "Success.");
	return true;
}

bool Client::sendFile()
{
	// send request
	Request request{};
	memcpy(request.header.client_id, mClientID.c_str(), 16);
	request.header.version = CLIENT_VERSION;
	request.header.code = REQUEST_SENDING_FILE;
	request.payload = buildRequestSendFilePayload(request.header.payload_size);
	sendRequest(request);
	delete[] request.payload;

	showLog("SEND FILE", "Success.");
	return true;
}

bool Client::checkAccept(int retries)
{
	// receive respond
	Respond respond{};
	receiveRespond(respond);
	if (respond.header.code != RESPOND_FILE_ACCEPTED || respond.payload == NULL) {
		if (respond.payload != NULL)
			delete[] respond.payload;
		showLog("CHECK ACCEPT", "Fail. Internal server error.");
		return false;
	}
	// parse payload
	RespondFileAcceptPayload respPayload = parseFileAcceptPayload(respond.payload, respond.header.payload_size);
	// check CRC
	CRC32 hash;
	string fileCRC;
	FileSource fs(mTransferFileName.c_str(), true, new HashFilter(hash, new HexEncoder(new StringSink(fileCRC), false)));

	bool success = true;
	Request request{};
	memcpy(request.header.client_id, mClientID.c_str(), 16);
	request.header.version = CLIENT_VERSION;
	if (respPayload.mCheckSumHex == fileCRC) {
		showLog("CHECK ACCEPT", "Success.");
		request.header.code = REQUEST_VALID_CRC;
	}
	else {
		showLog("CHECK ACCEPT", "Fail. CRC mismatch.");
		if (retries < MAX_RETRY_COUNT) {
			request.header.code = REQUEST_INVALID_CRC;
			success = false;
		}
		else 
			request.header.code = REQUEST_LAST_INVALID_CRC;
	}
	request.payload = buildRequestFileNamePayload(request.header.payload_size);
	sendRequest(request);
	delete[] request.payload;
	return success;
}

bool Client::confirmCRC(int retries)
{
	Respond respond;
	receiveRespond(respond);
	if (respond.header.code != RESPOND_MESSAGE_CONFIRMED || respond.payload == NULL) {
		if (respond.payload != NULL)
			delete[] respond.payload;
		showLog("CONFIRM", "Fail. Internal server error.");
		return false;
	}
	if (retries > MAX_RETRY_COUNT)
		showLog("CONFIRM", "Fail.");
	else
		showLog("CONFIRM", "Success. File transfer completed.");
	return true;
}


