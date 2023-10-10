#ifndef UTIL_HEADER_HPP
#define UTIL_HEADER_HPP

#include <iostream>
#include <cstring>
#include <fstream>
#include <string>
#include <stdio.h>
#include <limits>
#include <sstream> 
#include <vector>
#include <cstring>

#include "../Packets/StartPacket.hpp"
#include "../Packets/GenericPacket.hpp"
#include "../Packets/AuthenticationPacket.hpp"

using namespace std;

vector<uint8_t> serializeLoginMessage(string username, string password, int counter);
vector<uint8_t> serializeBalanceMessage(string username, int counter);
vector<uint8_t> serializeTransferMessage(string username, string other_username, int amount, int counter);
vector<uint8_t> serializeListOfTransfersMessage(string username, int T, int counter);
string* deserializeMessage(vector<uint8_t> serializedMessage);
vector<uint8_t> createSerializedPacket(vector<uint8_t>, size_t, vector<uint8_t>, vector<uint8_t>);
int convert_to_int(unsigned char*);
bool compare_to(unsigned char*, const char*);

vector<string> receiveResponseMessage(unsigned char* buff, ssize_t l, vector<uint8_t> key, vector<uint8_t> hmac_key, bool split = true);
vector<uint8_t> createResponseMessage(string msg, char delimiter = ',');
vector<string> splitString(const string &input, char delimiter);
string deserializeResponseMessage(string msg, char delimiter = ',');

#endif