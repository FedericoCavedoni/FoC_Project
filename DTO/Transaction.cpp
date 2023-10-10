#include "DTO.hpp"

int Transaction::counter = 0; 

Transaction::Transaction(){
    counter++;
    id = counter;       
    src = "";
    dest = "";
    amount = "";
    timestamp = "";
}
Transaction::Transaction(bool same){
    if(same){
        counter++;
    }
    id = counter;     
    src = "";
    dest = "";
    amount = "";
    timestamp = "";
}
Transaction::~Transaction(){}

int Transaction::getId(){
    return this->id;
}
string Transaction::getSrc(){
    return this->src;
}
string Transaction::getDest(){
    return this->dest;
}
string Transaction::getAmount(){
    return this->amount;
}
string Transaction::getTimestamp(){
    return this->timestamp;
}

void Transaction::setId(int id){
    this->id = id;
}
void Transaction::setSrc(string Src){
    this->src = Src;
}
void Transaction::setDest(string Dest){
    this->dest = Dest;
}
void Transaction::setAmount(string Amount){
    this->amount = Amount;
}
void Transaction::setTimestamp(string Timestamp){
    this->timestamp = Timestamp;
}

string Transaction::convertString(){
    string res = "";
    //res += to_string(getId())+":";
    res += "From:";
    res += getSrc();
    res += ", To:";
    res += getDest();
    res += ", Amount:";
    res += getAmount();
    res += ", Date:";
    res += getTimestamp();
    return res;   
}