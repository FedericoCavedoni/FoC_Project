#include "Client.hpp"

EVP_PKEY* PrivK = nullptr;
vector<uint8_t> symm_key_no_hashed;
vector<uint8_t> hmac_key_no_hashed;
vector<uint8_t> symm_key;
vector<uint8_t> hmac_key;

size_t symm_key_no_hash_size;
size_t hmac_key_no_hash_size;
unsigned int symm_key_size;
unsigned int hmac_key_size;

EVP_PKEY* symmetric_param;
EVP_PKEY* hmac_param;

int counter = 0;

Client::Client(string server_ip, int server_port){
    logged = false;
    recv_buffer = new unsigned char[MAX_MSG_SIZE];

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(sock_fd == -1)
        throw runtime_error("Failed to create socket!");

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    if(inet_pton(AF_INET, (const char*) server_ip.c_str(), &(server_addr.sin_addr)) <= 0)
        throw runtime_error("Invalid server IP address!");

    if(connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
        throw runtime_error("Failed to connect to the server!");

    cout << "Connected to the server." << endl;
}

Client::~Client(){
    close(sock_fd);
    delete[] recv_buffer;
}

bool Client::getLogged(){
    return this->logged;
}

bool Client::authentication(string username,string password){

    uint32_t len;

    EVP_PKEY* privK = read_private_key(username);
    if(privK == 0){
        cout<<endl<<"Wrong Username or Password Inserted"<<endl;
        return false;
    }

    send_to_server((void*)"Auth", strlen("Auth"));

    //Send Startacket to Server
    symmetric_param = generate_params();
    hmac_param = generate_params();

    StartPacket st = StartPacket(username, symmetric_param, hmac_param);
    
    vector<uint8_t> buffer = st.serialize();
    len = st.getLen();

    send_to_server(buffer.data(), len);

    uint32_t l;
    recv_from_server(l);
    
    if(strncmp((char*)recv_buffer, "NO", strlen("NO"))==0){
        cout<<"Wrong Username or Password Inserted"<<endl;
        return false;
    }   
    else if(strcmp((char*)recv_buffer, "")==0){
        cout<<"Wrong message received"<<endl;
        return false;
    }

    

    AuthenticationPacket at = AuthenticationPacket();
    vector<uint8_t> tmp(recv_buffer, recv_buffer + l);
    at.deserialize(tmp);

    generate_secrets(symmetric_param, at.getSymmetricParam(), symm_key_no_hashed, symm_key_no_hash_size);
    generate_secrets(hmac_param, at.getHmacParam(), hmac_key_no_hashed, hmac_key_no_hash_size);


    generateSHA(symm_key_no_hashed.data(), symm_key_no_hash_size, symm_key, symm_key_size);
    generateSHA(hmac_key_no_hashed.data(), hmac_key_no_hash_size, hmac_key, hmac_key_size);

    vector<uint8_t> str = at.getSign();

    vector<uint8_t> signed_text;

    cbc_decrypt(str, signed_text, at.getIv(), symm_key_no_hashed);
    removePKCS7Padding(signed_text);

    at.setSign(signed_text);

    vector<uint8_t> clear_text = at.serializeSign(symm_key, hmac_key);

    EVP_PKEY* server_pubk = read_server_public_key();

    if(!verify_signature(clear_text, signed_text, server_pubk)){
        cerr<<"Wrong Signature"<<endl;
        return false;
    }
    

    unsigned int symm_sign_len;
    unsigned int hmac_sign_len;

    vector<uint8_t> iv = generate_iv();
    AuthenticationPacket auth = AuthenticationPacket(iv, symmetric_param, hmac_param);

    generateSHA(symm_key_no_hashed.data(), symm_key_no_hash_size, symm_key, symm_key_size);
    generateSHA(hmac_key_no_hashed.data(), hmac_key_no_hash_size, hmac_key, hmac_key_size);


    vector<uint8_t> hashed = auth.serializeSign(symm_key, hmac_key);

    vector<uint8_t> signed_msg = sign_message(hashed, privK);
    vector<uint8_t> enc_buff;
    //cifrare in signed msg

    vector<uint8_t> padded_data(signed_msg);
    addPKCS7Padding(padded_data, EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    cbc_encrypt(padded_data, enc_buff, iv, symm_key_no_hashed);

    //invio auth msg
    auth.setSign(enc_buff);
    auth.setSign_len(enc_buff.size());
    auth.setIv(iv);

    vector<uint8_t> b =  auth.serialize();
    int buffer_len = auth.getLen();
    send_to_server(b.data(), buffer_len);
    
    recv_from_server(l);

    vector<string> msg = receiveResponseMessage(recv_buffer, l, symm_key_no_hashed, hmac_key_no_hashed);
    if(msg[0] == "OK")
        return true;
    else
        return false;

}

void Client::logIn(){
    string user;
    uint32_t len;

    cout << "Insert username: ";
    cin >> user;
    username = user;

    cout << "Insert password: "; 
    char *pwd = getpass("");
    string password(pwd);

    cout<<endl;

    if(!authentication(username, password)){
        cout<<"Authentication failed"<<endl<<endl;
        return;
    }


    counter = 0;

    vector<uint8_t> serializedMessage = serializeLoginMessage(username, password, counter);
    vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

    len = serializedPacket.size();
    send_to_server(serializedPacket.data(), len);
    counter = counter+1;

    recv_from_server(len);

    vector<string> msg = receiveResponseMessage(recv_buffer, len, symm_key_no_hashed, hmac_key_no_hashed);
    if(msg[0] == "OK"){
        cout<< "LOGGED IN"<<endl<<endl;
        this->logged = true;
    }else{
        cout<< "Wrong Username or Password Inserted"<<endl<<endl;
    }

};

void Client::logOut(){
    this->logged = false;
    counter = 0;
    send_to_server((void*)"LOGOUT", strlen("LOGOUT"));
    cout<<"LOGGED OUT"<<endl<<endl;
}
void Client::exitFunction(){
    send_to_server((void*)"EXIT", strlen("EXIT"));
}

void Client::send_to_server(void* buffer, uint32_t len){
    ssize_t ret;

    len++; // ''
    uint32_t actual_len = htonl(len);
    // send message length
    ret = send(sock_fd, &actual_len, sizeof(actual_len), 0);
    // -1 error, if returns 0 no bytes are sent
    if (ret <= 0)
    {
        cerr << "Error: message length not sent" << endl;
        return;
    }
    // send message
    ret = send(sock_fd, (void*)buffer, len, 0);
    // -1 error, if returns 0 no bytes are sent
    if (ret <= 0)
    {
        cerr << "Error: message not sent" << endl;
        return;
    }
};
void Client::recv_from_server(uint32_t &len){
    ssize_t ret;
    uint32_t size;
    // Receive message length
    memset(recv_buffer, 0, MAX_MSG_SIZE);
    ret = recv(sock_fd, &size, sizeof(uint32_t), 0);

    if (ret == 0){
        cerr << "ERR: server disconnected" << endl
             << endl;
        return;
    }

    try{
        // Allocate receive buffer
        len = ntohl(size);

        if(len > MAX_MSG_SIZE){
            len = MAX_MSG_SIZE;
        }

        if (!recv_buffer)
        {
            cerr << "ERR: recv_buffer malloc fail" << endl
                 << endl;
            throw 1;
        }
        // receive message
        ret = recv(sock_fd, (void*)recv_buffer, len, 0);
        if (ret == 0)
        {
            cerr << "ERR: Client disconnected" << endl
                 << endl;
            throw 2;
        }
    }
    catch (int error_code){

        free(recv_buffer);
        if (error_code == 2)
        {
            return;
        }
        else
        {
            return;
        }
    }
};

void Client::viewIdandBalance(){
    
    uint32_t len;

    vector<uint8_t> serializedMessage = serializeBalanceMessage(username, counter);
    vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

    len = serializedPacket.size();
    send_to_server(serializedPacket.data(), len);
    counter = counter+1;

    recv_from_server(len);
    if(strcmp((char*)recv_buffer, "")==0){
        cout<<"Wrong message received"<<endl;
        return;
    }

    vector<string> msg = receiveResponseMessage(recv_buffer, len, symm_key_no_hashed, hmac_key_no_hashed);


    cout<<endl;
    cout << "Account Id: " << msg[0] << endl;
    cout << "Balance: " << msg[1] << endl<<endl;
};

void Client::transfer(){
    string other_username;
    string amount;
    int amount_converted;
    uint32_t len;

    // send the other username
    cout << "Insert the other username: ";
    cin >> other_username;

    if(username == other_username){
        cout<<"You cannot send money to your username"<<endl<<endl;
        return;
    }

    // send the amount
    cout << "Insert the amount: ";
    cin >> amount;
    cout<<endl;

    try {
        amount_converted = stoi(amount);
    } catch (const invalid_argument &e) {
        cerr << "Wrong Input value"<< endl<<endl;
        return;
    }

    vector<uint8_t> serializedMessage = serializeTransferMessage(username, other_username, amount_converted, counter);
    vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);


    len = serializedPacket.size();
    send_to_server(serializedPacket.data(), len);
    counter = counter+1;

    recv_from_server(len);

    vector<string> msg = receiveResponseMessage(recv_buffer, len, symm_key_no_hashed, hmac_key_no_hashed);

    if(msg[0] == "OK"){
        cout<< "Transfer OK"<<endl<<endl;
    }else if(msg[0] == "NO1"){
        cout<< "Transfer Error: Username does not exist"<<endl<<endl;
    }
    else if(msg[0] == "NO2"){
        cout<< "Transfer Error: Not enought balance to make the transfer"<<endl<<endl;
    }
    else{
        cout<< "Transfer Error"<<endl<<endl;
    }

};

void Client::listOfTransfer(){
    string T;
    int T_converted;
    uint32_t len;

    // send T
    cout << "Insert the number of recent transactions you want to see: ";
    cin >> T;

    try {
        T_converted = stoi(T);
    } catch (const invalid_argument &e) {
        cerr << "Wrong Input value"<< endl<<endl;
        return;
    }

    vector<uint8_t> serializedMessage = serializeListOfTransfersMessage(username, T_converted, counter);
    vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

    len = serializedPacket.size();

    send_to_server(serializedPacket.data(), len);
    counter = counter+1;

    recv_from_server(len);
    vector<string> msg = receiveResponseMessage(recv_buffer, len, symm_key_no_hashed, hmac_key_no_hashed, false);
    msg = splitString(msg[0], ';');

    cout<<endl;
    cout << msg[0] << endl;
    cout << endl;
};

string Client::getUsername(){
    return username;
}

void Client::setLogged(bool b){
    this->logged = b;
}

void Client::send_int_to_server(uint32_t msg){
    ssize_t ret;
    // send message length
    msg = htonl(msg);
    ret = send(sock_fd, &msg, sizeof(uint32_t), 0);
    // -1 error, if returns 0 no bytes are sent
    if (ret <= 0)
    {
        cerr << "Error: message length not sent" << endl;
        return;
    }
}
        
int Client::recv_int_from_server(uint32_t &rcv_msg){
    ssize_t ret;
    // Receive message length
    ret = recv(sock_fd, &rcv_msg, sizeof(uint32_t), 0);

    if (ret == 0){
        cerr << "ERR: server disconnected" << endl
             << endl;
        return -1;
    }

    rcv_msg = ntohl(rcv_msg);
    return ret;
}
