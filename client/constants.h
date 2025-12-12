#pragma once
constexpr auto REQUEST_REGISTER = 1025;
constexpr auto REQUEST_SENDING_PUBKEY = 1026;
constexpr auto REQUEST_LOGIN = 1027;
constexpr auto REQUEST_SENDING_FILE = 1028;
constexpr auto REQUEST_VALID_CRC = 1029;
constexpr auto REQUEST_INVALID_CRC = 1030;
constexpr auto REQUEST_LAST_INVALID_CRC = 1031;

constexpr auto RESPOND_REGISTER_SUCCESS = 2100;
constexpr auto RESPOND_REGISTER_FAIL = 2101;
constexpr auto RESPOND_SENDING_ENCKEY = 2102;
constexpr auto RESPOND_FILE_ACCEPTED = 2103;
constexpr auto RESPOND_MESSAGE_CONFIRMED = 2104;
constexpr auto RESPOND_LOGIN_CONFIRMED = 2105;
constexpr auto RESPOND_LOGIN_REJECTED = 2106;

constexpr auto CLIENT_VERSION = 3;
constexpr auto MAX_RETRY_COUNT = 3;

constexpr auto TRANSFER_FILE = "transfer.info";
constexpr auto ME_FILE = "me.info";
constexpr auto PRIVATE_KEY_FILE = "priv.key";

