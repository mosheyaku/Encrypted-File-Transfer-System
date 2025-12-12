#pragma once
#include <string.h>
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <iostream>
#include "packets.h"
#include "crypt.h"

using namespace std;

class RespondClientIDPayload {
public:
	RespondClientIDPayload() {
		mClientID = "";
	}

	string mClientID;
};

class RespondShareKeyPayload {
public:
	RespondShareKeyPayload() {
		mClientID = "";
		mEncodedAesKey = "";
	}

	string mClientID;
	string mEncodedAesKey;
};

class RespondFileAcceptPayload {
public:
	RespondFileAcceptPayload() {
		mClientID = "";
		mContentSize = 0;
		mTransferFileName = "";
		mCheckSumHex = "";
	}

	string mClientID;
	int mContentSize;
	string mTransferFileName;
	string mCheckSumHex;
};


class Client
{
public:
	Client();
	~Client();

public:
	bool connectToServer();
	bool readSetting();
	bool reigster();
	bool shareKey();
	bool login();
	bool sendFile();
	bool checkAccept(int retries);
	bool confirmCRC(int retries);
	bool isRegistered() { return mRegistered; }

private:
	void sendRequest(Request request);
	void receiveRespond(Respond& respond);

	char* buildRequestNamePayload(uint32_t& payloadSize);
	char* buildRequestFileNamePayload(uint32_t& payloadSize);
	char* buildRequestShareKeyPayload(uint32_t& payloadSize);
	char* buildRequestSendFilePayload(uint32_t& payloadSize);

	RespondClientIDPayload parseClientIDPayload(char* payload, uint32_t payloadSize);
	RespondShareKeyPayload parseShareKeyPayload(char* payload, uint32_t payloadSize);
	RespondFileAcceptPayload parseFileAcceptPayload(char* payload, uint32_t payloadSize);

	string mServerIP; 
	int mServerPort; 

	string mClientID; 
	string mClientName; 
	
	string mTransferFileName; 
	bool mRegistered; 

	SOCKET mSocket; 
	
	Crypt mCrypt;
};

