#include "utilHeader.hpp"
#include "cryptoHeader.hpp"

#include <vector>

vector<uint8_t> serializeLoginMessage(string username, string password, int counter) {
    string serializedMessage = to_string(counter) + ",Login," + username + "," + password+',';
    vector<uint8_t> vec(serializedMessage.begin(), serializedMessage.end());
    return vec;
}


//pacchetto messaggio viewIdandBalance:    Balance,username
vector<uint8_t> serializeBalanceMessage(string username, int counter){
    string serializedMessage = to_string(counter) + ",Balance,"+username+',';
    vector<uint8_t> vec(serializedMessage.begin(), serializedMessage.end());
    return vec;
}

//pacchetto messaggio Transfer:    Transfer,username,other_username,amount
vector<uint8_t> serializeTransferMessage(string username, string other_username, int amount, int counter){
    string serializedMessage = to_string(counter) + ",Transfer,"+username+","+other_username+","+to_string(amount)+',';
    vector<uint8_t> vec(serializedMessage.begin(), serializedMessage.end());
    return vec;
}

//pacchetto messaggio ListOfTransfers:    List of Transfers,username,T
vector<uint8_t> serializeListOfTransfersMessage(string username, int T, int counter){
    string serializedMessage = to_string(counter) + ",List of Transfers,"+username+","+to_string(T)+',';
    vector<uint8_t> vec(serializedMessage.begin(), serializedMessage.end());
    return vec;
}

string* deserializeMessage(vector<uint8_t> serializedMessage){
    istringstream stream(string((char*)serializedMessage.data()));
    string* deserialized = new string[10];
    string token;
    int i = 0;
    while (getline(stream, token, ',')) {
        deserialized[i] = token;
        i++;
    }

    return deserialized; // ricordarsi di deallocare dove viene restituito !!!!!!!!!!!!!!!!
}

vector<uint8_t> createSerializedPacket(vector<uint8_t> serializedMessage, size_t mess_len, vector<uint8_t> symm_key_no_hashed, vector<uint8_t> hmac_key_no_hashed){
    vector<uint8_t> ciphertext;
    vector<uint8_t> digest;
    uint32_t digestlen;
    vector<uint8_t> iv = generate_iv();
    vector<uint8_t> ser_mes(serializedMessage.begin(), serializedMessage.begin()+mess_len);

    vector<uint8_t> padded_data(ser_mes);
    cbc_encrypt(padded_data, ciphertext, iv, symm_key_no_hashed);
    generateHMAC(ciphertext.data(), ciphertext.size(), digest, digestlen, hmac_key_no_hashed);
    
    GenericPacket gp(iv, ciphertext.size(), ciphertext, digest);
    vector<uint8_t> serializedPacket = gp.serialize();
    return serializedPacket;
}

int convert_to_int(unsigned char* buffer){
    int value = 0;
    for(int i = 0; i < sizeof(buffer); i++){
        value = (value << 8) | buffer[i];        
    }

    return value;
}

bool compare_to(unsigned char* buf, const char* cmd){
    for (size_t i = 0; i < sizeof(cmd); i++) {
        if (buf[i] != cmd[i]) {
            return false; 
        }
    }
    return true;
}

vector<uint8_t> createResponseMessage(string msg, char delimiter){
    string message = msg + delimiter;
    vector<uint8_t> vec(message.begin(), message.end());
    return vec;
}

vector<string> receiveResponseMessage(unsigned char* buff, ssize_t len, vector<uint8_t> key, vector<uint8_t> hmac_key, bool split){
    GenericPacket gp; 
    vector<uint8_t> tmp(buff, buff+len);

    gp.deserialize(tmp);
    vector<uint8_t> plaintext;
    cbc_decrypt(gp.getCiphertext(), plaintext, gp.getIv(), key);

    // HMAC
    vector<unsigned char> hmac = gp.getHMAC();
    if(!verifyHMAC(gp.getCiphertext().data(), gp.getCipherLen(), hmac, hmac_key)){
        cout << "Errore nella verifica del messaggio" << endl;
        return {"",};
    }

    vector<string> msg;
    if(split)
        msg = splitString(string((char*)plaintext.data()), ',');
    else
        msg.push_back(string((char*)plaintext.data()));

    return msg;
}

vector<string> splitString(const string &input, char delimiter) {
    vector<string> tokens;
    stringstream ss(input);
    string token;

    while (getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}

string deserializeResponseMessage(string msg, char delimiter) {
    istringstream iss(msg);
    string temp;

    if (getline(iss, temp, delimiter)) {
        return temp;
    }
    return "";
}