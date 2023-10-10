#include "StartPacket.hpp"

unsigned char start_buff[MAX_MSG_SIZE];

StartPacket::StartPacket(){}

StartPacket::StartPacket(string username){
    this->username = username;
    this->username_len = username.size();
    this->symmetric_param = nullptr;
    this->hmac_param = nullptr; 
}

StartPacket::StartPacket(string username, EVP_PKEY* sym_param, EVP_PKEY* hmac_param){
    this->username = username;
    this->username_len = username.size();
    this->symmetric_param = sym_param;
    this->hmac_param = hmac_param;
}

StartPacket::~StartPacket() {
    EVP_PKEY_free(symmetric_param);
    EVP_PKEY_free(hmac_param);
}

string StartPacket::getUsername(){
    return this->username;
}

EVP_PKEY* StartPacket::getSymmEVP(){
    return this->symmetric_param;
}

EVP_PKEY* StartPacket::getHmacEVP(){
    return this->hmac_param;
}

uint32_t StartPacket::getUsernameLen(){
    return username_len;
}

uint32_t StartPacket::getSymmetricParamLen(){
    return symmetric_param_len;
}

uint32_t StartPacket::getHmacParamLen(){
    return hmac_param_len;
}

vector<uint8_t> StartPacket::serialize(){
    vector<uint8_t> serialized_data;

    //setting the correct length of the bio param
    vector<uint8_t> symmetric_param_buf = serializeKey(symmetric_param);
    symmetric_param_len = symmetric_param_buf.size();

    vector<uint8_t> hmac_param_buf = serializeKey(hmac_param);
    hmac_param_len = hmac_param_buf.size();

    // Serializing username_len, symmetric_param_len, and hmac_param_len
    serialized_data.resize(3 * MAX_NUM_CIPHER);
    size_t offset = 0;

    string s = to_string(username_len);
    addZeros(s, MAX_NUM_CIPHER);
    memcpy(serialized_data.data() + offset, s.c_str(), MAX_NUM_CIPHER);
    offset += MAX_NUM_CIPHER;

    s = to_string(symmetric_param_len);
    addZeros(s, MAX_NUM_CIPHER);
    memcpy(serialized_data.data() + offset, s.c_str(), MAX_NUM_CIPHER);
    offset += MAX_NUM_CIPHER;

    s = to_string(hmac_param_len);
    addZeros(s, MAX_NUM_CIPHER);
    memcpy(serialized_data.data() + offset, s.c_str(), MAX_NUM_CIPHER);
    offset += MAX_NUM_CIPHER;

    // Serializing username
    vector<uint8_t> username_bytes(username.begin(), username.end());
    serialized_data.insert(serialized_data.end(), username_bytes.begin(), username_bytes.end());

    // Serializing symmetric_param
    serialized_data.insert(serialized_data.end(), symmetric_param_buf.begin(), symmetric_param_buf.end());

    // Serializing hmac_param
    serialized_data.insert(serialized_data.end(), hmac_param_buf.begin(), hmac_param_buf.end());

    return serialized_data;
}

void StartPacket::deserialize(const vector<uint8_t>& serialized_data) {
    size_t offset = 0;
    string tmp;

    // Deserializing username_len
    tmp.assign(serialized_data.begin() + offset, serialized_data.begin() + offset + MAX_NUM_CIPHER);
    username_len = stoi(tmp);
    offset += MAX_NUM_CIPHER;

    // Deserializing symmetric_param_len
    tmp.assign(serialized_data.begin() + offset, serialized_data.begin() + offset + MAX_NUM_CIPHER);
    symmetric_param_len = stoi(tmp);
    offset += MAX_NUM_CIPHER;

    // Deserializing hmac_param_len
    tmp.assign(serialized_data.begin() + offset, serialized_data.begin() + offset + MAX_NUM_CIPHER);
    hmac_param_len = stoi(tmp);
    offset += MAX_NUM_CIPHER;

    // Deserializing username
    username.assign(serialized_data.begin() + offset, serialized_data.begin() + offset + username_len);
    offset += username_len;

    // Deserializing symmetric_param
    vector<uint8_t> symmetric_param_buf(serialized_data.begin() + offset, serialized_data.begin() + offset + symmetric_param_len);
    symmetric_param = deserializeKey(symmetric_param_buf.data(), symmetric_param_len);
    offset += symmetric_param_len;

    // Deserializing hmac_param
    vector<uint8_t> hmac_param_buf(serialized_data.begin() + offset, serialized_data.begin() + offset + hmac_param_len);
    hmac_param = deserializeKey(hmac_param_buf.data(), hmac_param_len);
}


uint32_t StartPacket::getLen(){
    return MAX_NUM_CIPHER*3 + username_len + symmetric_param_len + hmac_param_len;
}
