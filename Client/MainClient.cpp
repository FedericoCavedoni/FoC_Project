#include "Client.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/evp.h>


void startingMenu(Client &);
void loggedMenu(Client &);

int main(int argc, char* argv[]) {

    OpenSSL_add_all_algorithms();
    
    if(argc != 2){
        cerr<<"Correct usage: ./client SERVER_PORT"<<endl;
        return -1;
    }

    string server_ip = "127.0.0.1";
    int server_port = atoi(argv[1]);
    Client client(server_ip, server_port);

    try{
        while(true){
            if(client.getLogged() == true){
                loggedMenu(client);
            }else{
                startingMenu(client);
            }
        }
            
    }catch(const runtime_error& ex) {
        cerr << ex.what() << endl;
        return -1;
    }
    
    return 0;
}

void startingMenu(Client &client){
    int choice = 0;
    string c;
    bool control = false;

   while (!control){
        cout << "SECURE BANKING APPLICATION" << endl<<endl;
        cout << "1. Log In" << endl;
        cout << "2. Exit"<< endl;
        cout << "Choose an option "<<endl<<endl;
        cin >> c;

        try {
            choice = stoi(c);
        } catch (invalid_argument const& e) {
            cerr << "Wrong input value, try again"<<endl<<endl;
            break;
        }        

        switch (choice) {
            case 1:
                client.logIn();
                control = true;
                break;
            case 2:
                cout<<"Closing the program..."<<endl;
                client.exitFunction();
                exit(0);

            default:
                cout << "Invalid option, try again" <<endl<<endl;
                break;
        }
    }  
}

void loggedMenu(Client &client){
    string c;
    bool control = false;
    int choice = 0;

     while (!control){

        cout << "Menu:" << endl;
        cout << "1. View account Id and Balance" << endl;
        cout << "2. Make a Transfer" << endl;
        cout << "3. View list of transfers"<< endl;
        cout << "4. Log Out" << endl;
        cout << "Choose an option "<<endl<<endl;
        cin >> c;

        try {
            choice = stoi(c);
        } catch (invalid_argument const& e) {
            cerr << "Wrong input value, try again"<<endl<<endl;
            break;
        }

        switch (choice) {
            case 1:
                client.viewIdandBalance();
                break;
            case 2:
                client.transfer();
                break;
            case 3:
                client.listOfTransfer();
                break;
            case 4:
                client.logOut();
                control = true;
                client.setLogged(false);
                break;
            default:
                cout << "Invalid option, try again" <<endl<<endl;
                break;
        }
    }
}