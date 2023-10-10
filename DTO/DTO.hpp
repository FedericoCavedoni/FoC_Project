#ifndef DTO_HPP
#define DTO_HPP

#include "../Util/utilHeader.hpp"

class Transaction{
    private:
        static int counter;
        int id;
        string src;
        string dest;
        string amount;
        string timestamp;

    public:
        Transaction();
        Transaction(bool);
        ~Transaction();

        int getId();
        string getSrc();
        string getDest();
        string getAmount();
        string getTimestamp();

        void setId(int);
        void setSrc(string);
        void setDest(string);
        void setAmount(string);
        void setTimestamp(string);
        string convertString();

};

class User{
    private:
        int id;
        string Username;
        string password;
        string balance;
        string salt;
        int counter;

    public:
        User();
        ~User();
        
        int getId();
        string getUsername();
        string getPassword();
        string getBalance();
        string getSalt();

        void setId(int);
        void setUsername(string);
        void setPassword(string);
        void setBalance(string);  
        void setSalt(string);

        void setCounter(int c);
        int getCounter();
};

#endif