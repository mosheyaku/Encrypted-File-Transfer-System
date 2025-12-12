#pragma once
#include <stdint.h>

#pragma pack(push, 1)
struct RequestHeader {
	char client_id[16];
	uint8_t version;
	uint16_t code;
	uint32_t payload_size;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct RespondHeader {
	uint8_t version;
	uint16_t code;
	uint32_t payload_size;
};
#pragma pack(pop)

struct Request {
	RequestHeader header;
	char* payload;
};

struct Respond {
	RespondHeader header;
	char* payload;
};
