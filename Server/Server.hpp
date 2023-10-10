#ifndef SERVER_HPP
#define SERVER_HPP

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/rand.h>
#include <openssl/aes.h>

#include <iostream>
#include "../Filemanager/FileManager.hpp"

#include <thread>
#include <mutex>


class Server{
    public:

        Server(int port, int backlog);
        ~Server();
        int getPort();
        int getBacklog();
        sockaddr_in getAddress();
        void handle_connections();
        void handle_client_disconnection(int);
        void handle_command(string* fields, int comm_sock, vector<uint8_t> &symm_key_no_hashed, vector<uint8_t> &hmac_key_no_hashed, size_t &symm_key_no_hash_size, size_t &hmac_key_no_hash_size, unsigned int &symm_key_size, unsigned int &hmac_key_size);
        
    private:
        fd_set read_fds;
        fd_set master;
        int fdmax;
        int port;
        int sock_fd;
        int backlog;
        unsigned char* receive_buffer;
        uint32_t receive_msg_len;
        sockaddr_in address;

        void handle_clients(int new_sd);
        void handle_socket();
        void setup();
        void send_message(int currentSocket, const void *msg, const uint32_t len);
        int receive_message(int i);
        void send_int(int currentSocket, const uint32_t msg);
        int receive_int(int i);
            
};

#endif