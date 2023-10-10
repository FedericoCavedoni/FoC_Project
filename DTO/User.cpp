#include "DTO.hpp"

User::User(){
    id = 0;
    Username = "";
    password = "";
    balance = "";
    salt = "";
    counter = 0;
}
User::~User(){}

int User::getId(){
    return this->id;
}
string User::getUsername(){
    return this->Username;
}
string User::getPassword(){
    return this->password;
}
string User::getBalance(){
    return this->balance;
}
string User::getSalt(){
    return this->salt;
}

void User::setId(int id){
    this->id = id;
}
void User::setUsername(string username){
    this->Username = username;
}
void User::setPassword(string password){
    this->password = password;
}
void User::setBalance(string balance){
    this->balance = balance;
}
void User::setSalt(string Salt){
    this->salt = Salt;
}

int User::getCounter(){
    return this->counter;
}

void User::setCounter(int c){
    this->counter = c;
}