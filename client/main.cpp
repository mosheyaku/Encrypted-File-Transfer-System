// main.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string.h>
#include "constants.h"
#include "client.h"

using namespace std;

int main()
{
	Client client;
	// read setting
	if (!client.readSetting()) return -1;
	// connect to server
	if (!client.connectToServer()) return -1;
	
	if (!client.isRegistered()) { // register client to server
		if (!client.reigster()) return -1;
		if (!client.shareKey()) return -1;
	}
	else { // login
		if (!client.login()) return -1;
	}
	// try to send file
	int retryCount = 0;
	while (retryCount < MAX_RETRY_COUNT) {
		retryCount++;
		if (!client.sendFile()) continue; // send file
		if (!client.checkAccept(retryCount)) continue; // check accept
		if (!client.confirmCRC(retryCount)) continue; // check confirm
		break;
	}

	return 0;
}