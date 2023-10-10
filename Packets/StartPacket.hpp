#ifndef STARTPACKET_HPP
#define STARTPACKET_HPP

#include "../Util/cryptoHeader.hpp"

using namespace std;

class StartPacket{
    private:
        uint32_t username_len;
        uint32_t symmetric_param_len;
        uint32_t hmac_param_len;

        string username;
        EVP_PKEY* symmetric_param;
        EVP_PKEY* hmac_param;

    public:
        StartPacket();
        StartPacket(string username);
        StartPacket(string username, EVP_PKEY* sym_param, EVP_PKEY* hmac_param);
        ~StartPacket();

        string getUsername();
        EVP_PKEY* getSymmEVP();
        EVP_PKEY* getHmacEVP();
        uint32_t getUsernameLen();
        uint32_t getSymmetricParamLen();
        uint32_t getHmacParamLen();
        uint32_t getLen();

        vector<uint8_t> serialize();
        void deserialize(const vector<uint8_t>& serialized_data);
};

#endif