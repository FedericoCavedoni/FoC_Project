#include "Server.hpp"

EVP_PKEY* privK = nullptr;


// Genera un vettore di inizializzazione (IV) casuale
vector<uint8_t> iv_file(AES_BLOCK_SIZE);
vector<uint8_t> key_file(KEY_SIZE);

vector<thread> client_threads;
mutex client_threads_mutex;

void reset_files() {
    string nome_file1 = "Users/giova/transactions.txt";
    string nome_file2 = "Users/giova/transactions_enc.txt";
    string nome_file3 = "Users/fede/transactions.txt";
    string nome_file4 = "Users/fede/transactions_enc.txt";

    // Apri e svuota il contenuto dei file
    ofstream file1(nome_file1);
    ofstream file2(nome_file2);
    ofstream file3(nome_file3);
    ofstream file4(nome_file4);

    if (file1.is_open() && file2.is_open() && file3.is_open() && file4.is_open()) {
        // Chiudi i file dopo averli svuotati
        file1.close();
        file2.close();
        file3.close();
        file4.close();
    } else {
        cerr << "Unable to reset files" << endl;
    }
}

bool userExist(User user){
    if(user.getId() == 0){
        return false;
    }
    return true;
}

string getCurrentTimestamp();

Server::Server(int port, int backlog){
    receive_buffer = new unsigned char[MAX_MSG_SIZE];

    if(port < 49152 && port > 65535 )
        throw invalid_argument("Invalid port");

    if(backlog < 0)
        throw invalid_argument("Invalid backlog");
    this->port = port;
    this->backlog = backlog;

    RAND_bytes(iv_file.data(), iv_file.size());
    RAND_bytes(key_file.data(), KEY_SIZE);

    handle_socket();
    setup();
}

Server::~Server(){
    if (sock_fd != -1) 
        close(sock_fd);

    delete[] receive_buffer;
}

int Server::getPort(){
    return this->port;
}

int Server::getBacklog(){
    return this->backlog;
}

sockaddr_in Server::getAddress(){
    return this->address;
}

void Server::handle_socket(){
    // create socket
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (sock_fd == -1) 
    {
        throw runtime_error("Failed in creating socket");
    }

    // bind socket
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(sock_fd, (struct sockaddr*) &address, sizeof(address)) == -1) 
    {
        throw runtime_error("Failed in binding socket");
    }

    // listen 
    if (listen(sock_fd, backlog) == -1) 
    {
        throw runtime_error("Error in listen");
    }
}

void Server::handle_clients(int new_sd){
    vector<uint8_t> symm_key_no_hashed;
    vector<uint8_t> hmac_key_no_hashed;

    size_t symm_key_no_hash_size;
    size_t hmac_key_no_hash_size;
    unsigned int symm_key_size;
    unsigned int hmac_key_size;

    while(1){

        receive_message(new_sd);

        if(strncmp((char*)receive_buffer, "Auth", strlen("Auth")) == 0){
            string buf[] = {"0", "Auth"};
            handle_command(buf, new_sd, symm_key_no_hashed, hmac_key_no_hashed, symm_key_no_hash_size, hmac_key_no_hash_size, symm_key_size, hmac_key_size);
        }
        else if(strncmp((char*)receive_buffer, "LOGOUT", strlen("LOGOUT")) == 0){
            std::cout<<"LOGOUT"<<endl;
        }
        else if(strncmp((char*)receive_buffer, "EXIT", strlen("EXIT")) == 0){
            std::cout<<"EXIT"<<endl;
            handle_client_disconnection(new_sd);
            break;
        }
        else if(strcmp((char*)receive_buffer, "") == 0){ //disconnessione improvvisa client
            std::cout<<"CLIENT DISCONNECTED"<<endl;
            handle_client_disconnection(new_sd);
            break;
        }
        else if(strncmp((char*)receive_buffer, "ERROR", strlen("ERROR")) == 0){ //errore client
            std::cout<<"CLIENT DISCONNECTED"<<endl;
            handle_client_disconnection(new_sd);
            break;
        }
        else{
            GenericPacket gp; 
            ssize_t len = ntohl(receive_msg_len);
            vector<uint8_t> tmp(receive_buffer, receive_buffer+len);

            gp.deserialize(tmp);
            vector<uint8_t> plaintext;
            cbc_decrypt(gp.getCiphertext(), plaintext, gp.getIv(), symm_key_no_hashed);

            // HMAC
            vector<unsigned char> hmac = gp.getHMAC();
            if(!verifyHMAC(gp.getCiphertext().data(), gp.getCipherLen(), hmac, hmac_key_no_hashed)){
                std::cout << "Errore nella verifica del messaggio" << endl;
            } else{
                string* deserializedMessage = deserializeMessage(plaintext);
                handle_command(deserializedMessage, new_sd, symm_key_no_hashed, hmac_key_no_hashed, symm_key_no_hash_size, hmac_key_no_hash_size, symm_key_size, hmac_key_size);
            }
        }
    }

}

void Server::handle_connections(){
    //reset_files();

    while(true){
        struct sockaddr_in cl_addr;   
        int len = sizeof(cl_addr);
        int new_sd = accept(sock_fd, (struct sockaddr*) &cl_addr, (socklen_t*) &len);

        if(new_sd == -1){
            cerr << "Error in accepting the connession" << endl;
            continue;
        }

        thread client_thread(&Server::handle_clients, this, new_sd);
        lock_guard<mutex> lock(client_threads_mutex);
        client_threads.push_back(move(client_thread));
    }
    
}


void Server::setup(){
    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    FD_SET(sock_fd, &master); 
    FD_SET(0, &master);
    fdmax = sock_fd;
    reset_files();
}

void Server::handle_client_disconnection(int sock){
    close(sock);
    FD_CLR(sock, &master);
    lock_guard<mutex> lock(client_threads_mutex);
    
    for (auto it = client_threads.begin(); it != client_threads.end(); ++it) {
        if (it->get_id() == std::this_thread::get_id()) {
            it->detach(); // Rilascia il thread
            client_threads.erase(it);
            break;
        }
    }
}


void Server::handle_command(string* fields, int comm_sock, vector<uint8_t> &symm_key_no_hashed, vector<uint8_t> &hmac_key_no_hashed, size_t &symm_key_no_hash_size, size_t &hmac_key_no_hash_size, unsigned int &symm_key_size, unsigned int &hmac_key_size){

    int counter = stoi(fields[0]);
    string cmd = fields[1];

    if(cmd == "Auth"){
        vector<uint8_t> symm_key;
        vector<uint8_t> hmac_key;

        receive_message(comm_sock);
        if(strcmp((char*)receive_buffer, "")==0){
            return;
        }

        StartPacket st;

        vector<uint8_t> tmp(receive_buffer, receive_buffer+strlen((char*)receive_buffer));
        st.deserialize(tmp);

        FileManager fm(st.getUsername());
        if(!userExist(fm.getUser())){
            send_message(comm_sock, "NO", strlen("NO"));
            return;
        }

        EVP_PKEY* symmetric_param = generate_params();
        EVP_PKEY* hmac_param = generate_params();

        generate_secrets(symmetric_param, st.getSymmEVP(), symm_key_no_hashed, symm_key_no_hash_size);
        generate_secrets(hmac_param, st.getHmacEVP(), hmac_key_no_hashed, hmac_key_no_hash_size);

        generateSHA(symm_key_no_hashed.data(), symm_key_no_hash_size, symm_key, symm_key_size);
        generateSHA(hmac_key_no_hashed.data(), hmac_key_no_hash_size, hmac_key, hmac_key_size);


        //Derive private key

        privK = read_server_private_key();

        vector<uint8_t> iv = generate_iv();

        unsigned int len_sign;

        AuthenticationPacket ap(iv, symmetric_param, hmac_param);

        vector<uint8_t> hashed = ap.serializeSign(symm_key, hmac_key);

        vector<uint8_t> sign = sign_message(hashed, privK);

        vector<uint8_t> sign_cipher;
        vector<uint8_t> padded_data(sign);
        addPKCS7Padding(padded_data, EVP_CIPHER_block_size(EVP_aes_256_cbc()));

        cbc_encrypt(padded_data, sign_cipher, iv , symm_key_no_hashed);

        //sending login message to client
        ap.setSign_len(sign_cipher.size());
        ap.setSign(sign_cipher);

        vector<uint8_t> s;
        ap.setIv(iv);

        vector<uint8_t> msg = ap.serialize();
        ssize_t len = ap.getLen();
        send_message(comm_sock, msg.data(), len);

        //Ricevere auth da client
        vector<uint8_t> plaintext;

        receive_message(comm_sock);
        if(strcmp((char*)receive_buffer, "")==0){
            return;
        }


        AuthenticationPacket at = AuthenticationPacket();
        int lm = ntohl(receive_msg_len);
        vector<uint8_t> r_vec(receive_buffer, receive_buffer + lm);

        at.deserialize(r_vec);

        vector<uint8_t> sign_enc = at.getSign();

        //decrypt
        cbc_decrypt(sign_enc, plaintext, at.getIv(), symm_key_no_hashed);
        removePKCS7Padding(plaintext);
        at.setSign(plaintext);
     
        vector<uint8_t> clear_text = at.serializeSign(symm_key, hmac_key);
        
        EVP_PKEY* client_pubk = read_public_key(st.getUsername());
        if(!verify_signature(clear_text, plaintext, client_pubk)){
            cerr<<"Wrong Signature";

            vector<uint8_t> serializedMessage = createResponseMessage(string("NO"));
            vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

            int len = serializedPacket.size();
            send_message(comm_sock, serializedPacket.data(), len);
            return;
        }

        vector<uint8_t> serializedMessage = createResponseMessage(string("OK"));
        vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

        len = serializedPacket.size();
        send_message(comm_sock, serializedPacket.data(), len);

        EVP_PKEY_free(symmetric_param);
        EVP_PKEY_free(hmac_param);

        return;
    }
    if(cmd == "Login"){

        string username = fields[2];
        string password = fields[3];

        // control the credentials
        FileManager fm(username);
        fm.resetCounter(username);

        User user = fm.getUser();
        int c = user.getCounter();

        if(counter != c){
            cerr<<"Wrong counter, old message detected"<<endl;

            vector<uint8_t> serializedMessage = createResponseMessage(string("NO"));
            vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

            int len = serializedPacket.size();
            send_message(comm_sock, serializedPacket.data(), len);
            return;
        }

        fm.updateCounter(username);
        string salt = user.getSalt();
        string pwd_salted = salt + password;

        vector<uint8_t> input_pwd(pwd_salted.begin(), pwd_salted.end());

        string pwd_str = user.getPassword();
        vector<uint8_t> pwd(pwd_str.begin(), pwd_str.end());
        unsigned char* hash = pwd.data();

        if(verifySHA(input_pwd.data(), input_pwd.size(), hash)){
            vector<uint8_t> serializedMessage = createResponseMessage(string("OK"));
            vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

            int len = serializedPacket.size();
            send_message(comm_sock, serializedPacket.data(), len);
            cout << "LOGIN" << endl;
        }
        else{
            vector<uint8_t> serializedMessage = createResponseMessage(string("NO"));
            vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

            int len = serializedPacket.size();
            send_message(comm_sock, serializedPacket.data(), len);
        }

        return;
    }

    if(cmd == "Balance"){
        
        string username = fields[2];

        FileManager fm(username);
        User user = fm.getUser();

        if(counter != user.getCounter()){
            cerr<<"Wrong counter, old message detected"<<endl;
            vector<uint8_t> serializedMessage = createResponseMessage(string("NO"));
            vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

            int len = serializedPacket.size();
            send_message(comm_sock, serializedPacket.data(), len);
            return;
        }

        fm.updateCounter(username);
        int accountId = user.getId();

        string serializedIdBalance = to_string(accountId);
        serializedIdBalance += ',';
        serializedIdBalance += user.getBalance();
        serializedIdBalance += ',';
        
        vector<uint8_t> serializedMessage = createResponseMessage(serializedIdBalance);
        vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);
        int len = serializedPacket.size();
        send_message(comm_sock, serializedPacket.data(), len);

        cout << "BALANCE" << endl;
        return;
    }

    if(cmd == "Transfer"){

        string username = fields[2];
        string other_username = fields[3];
        int amount = stoi(fields[4]);


        //decrypt transfer file;
        string clearFile = "Users/" + username + "/transactions.txt";
        string encFile = "Users/" + username + "/transactions_enc.txt";
        decryptFile((char*)encFile.c_str(), (char*)clearFile.c_str(), key_file.data()); 
        
        string clearFile1 = "Users/" + other_username + "/transactions.txt";
        string encFile1 = "Users/" + other_username + "/transactions_enc.txt";
        decryptFile((char*)encFile1.c_str(), (char*)clearFile1.c_str(), key_file.data()); 

        // do the transfer 
        FileManager fm(username);
        FileManager fm2(other_username);
        User user = fm.getUser();
        User user2 = fm2.getUser();

        if(counter != user.getCounter()){
            cerr<<"Wrong counter, old message detected"<<endl;
            vector<uint8_t> serializedMessage = createResponseMessage(string("NO"));
            vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

            int len = serializedPacket.size();
            send_message(comm_sock, serializedPacket.data(), len);
            return;
        }

        fm.updateCounter(username);


        if(!userExist(user2)){
            vector<uint8_t> serializedMessage = createResponseMessage(string("NO1"));
            vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

            int len = serializedPacket.size();
            send_message(comm_sock, serializedPacket.data(), len);
            return;
        }

        float balance = stof(user.getBalance());
        string msg;


        if(balance < amount){
            msg = "NO2";
        }else{
            msg = "OK";
            fm.updateBalance(username, to_string(balance-amount));

            float balanceRec = stof(user2.getBalance());
            fm.updateBalance(other_username, to_string(balanceRec+amount));

            fm.insertTransaction(other_username, to_string(amount));
            fm2.receiveTransaction(username, to_string(amount));
        
            cout << "TRANSFER" << endl;
        }

        vector<uint8_t> serializedMessage = createResponseMessage((msg));
        vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

        int len = serializedPacket.size();
        send_message(comm_sock, serializedPacket.data(), len);

        //encrypt transfer file;
        clearFile = "Users/" + username + "/transactions.txt";
        encFile = "Users/" + username + "/transactions_enc.txt";
        encryptFile((char*)clearFile.c_str(), (char*)encFile.c_str(), key_file.data(), iv_file.data());

        ofstream f(clearFile);
        if (!f.is_open()) {
            cerr << "Errore nell'apertura del file." << endl;
        } else{
            f << "";
            f.close();
        }

        clearFile = "Users/" + other_username + "/transactions.txt";
        encFile = "Users/" + other_username + "/transactions_enc.txt";
        encryptFile((char*)clearFile.c_str(), (char*)encFile.c_str(), key_file.data(), iv_file.data());

        ofstream f1(clearFile);
        if (!f1.is_open()) {
            cerr << "Errore nell'apertura del file." << endl;
        } else{
            f1 << "";
            f1.close();
        }

        return;
    }

    if(cmd == "List of Transfers"){

        string username = fields[2];
        int T = stoi(fields[3]);


        //decrypt transfer file;
        string clearFile = "Users/" + username + "/transactions.txt";
        string encFile = "Users/" + username + "/transactions_enc.txt";
        decryptFile((char*)encFile.c_str(), (char*)clearFile.c_str(), key_file.data()); 

        // receive T
        int num = 0;

        // retrieve list of transfers
        FileManager fm(username);
        User user = fm.getUser();

        if(counter != user.getCounter()){
            cerr<<"Wrong counter, old message detected"<<endl;
            vector<uint8_t> serializedMessage = createResponseMessage(string("NO"));
            vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);

            int len = serializedPacket.size();
            send_message(comm_sock, serializedPacket.data(), len);
            return;
        }

        fm.updateCounter(username);
        Transaction* list = fm.getTransactions(username, T, num);

        // parse the result in one message
        string list_of_transfers = "";
        for(int i = 0; i < num; i++)
            list_of_transfers = list_of_transfers + list[i].convertString() + "\n";
        
        vector<uint8_t> serializedMessage = createResponseMessage(list_of_transfers, ';');
        vector<uint8_t> serializedPacket = createSerializedPacket(serializedMessage, serializedMessage.size(), symm_key_no_hashed, hmac_key_no_hashed);
        int len = serializedPacket.size();
        send_message(comm_sock, serializedPacket.data(), len);


        ofstream f1(clearFile);
        if (!f1.is_open()) {
            cerr << "Errore nell'apertura del file." << endl;
        } else{
            f1 << "";
            f1.close();
        }


        cout << "LIST OF TRANSFERS" << endl;

        return;
    }

    delete[] fields;

}

void Server::send_message(int currentSocket, const void *msg, uint32_t len)
{
    ssize_t ret;
    len++;
    uint32_t actual_len = htonl(len);
    // Send message length
    ret = send(currentSocket, &actual_len, sizeof(actual_len), 0);
    // If -1 error it means that no bytes were sent
    if (ret <= 0)
    {
        cerr << "ERR: Message length not sent" << endl
             << endl;
        return;
    }
    // Send message
    ret = send(currentSocket, msg, len, 0);
    // If -1 error it means that no bytes were sent
    if (ret <= 0)
    {
        cerr << "ERR: Message not sent" << endl
             << endl;
        return;
    }
}

int Server::receive_message(int i)
{
    memset(receive_buffer, 0, MAX_MSG_SIZE);

    int ret = recv(i, (void*)&receive_msg_len, sizeof(uint32_t), 0);
    if(ret < 0){
        cerr<<"Error in receiving the message"<<endl;;
        return -1;
    }

    int len = ntohl(receive_msg_len);
    if(len > MAX_MSG_SIZE){
            len = MAX_MSG_SIZE;
    }
    // disconnessione improvvisa del client
    if(ret == 0){
        handle_client_disconnection(i);
        return -1;
    }
    

    ret = recv(i, receive_buffer, len, 0);
    if(ret < 0){
        perror("Errore in fase di ricezione: ");
        return -1;
    }

    // disconnessione improvvisa del client
    if(ret == 0){
        handle_client_disconnection(i);
        return -1;
    }

    return 0;
}

void Server::send_int(int currentSocket, const uint32_t msg)
{
    ssize_t ret;
    // Send message
    uint32_t msg_to_net = htonl(msg);
    ret = send(currentSocket, (void*) &msg_to_net, sizeof(uint32_t), 0);
    // If -1 error it means that no bytes were sent
    if (ret <= 0)
    {
        cerr << "ERR: Message not sent" << endl
             << endl;
        return;
    }
}

int Server::receive_int(int i)
{
    uint32_t receive_msg;

    int ret = recv(i, (void*)&receive_msg, sizeof(uint32_t), 0);
    if(ret < 0){
        cerr<<"Error in receiving the message"<<endl;;
        return -1;
    }

    int msg = ntohl(receive_msg);
    // disconnessione improvvisa del client
    if(ret == 0){
        handle_client_disconnection(i);
        return -1;
    }
    

    return msg;
}

string getCurrentTimestamp() {
    auto now = chrono::system_clock::now();

    auto ms = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()) % 1000;

    time_t timestamp = chrono::system_clock::to_time_t(now);

    stringstream ss;
    ss << put_time(localtime(&timestamp), "%Y-%m-%d %H:%M:%S")
       << '.' << setfill('0') << setw(3) << ms.count();

    return ss.str();
}
