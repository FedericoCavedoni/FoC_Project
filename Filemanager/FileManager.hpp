#ifndef FILEMANAGER_HPP
#define FILEMANAGER_HPP

#include <filesystem>
#include <iomanip>
#include <sstream>

#include "../DTO/DTO.hpp"

class FileManager {
    private:
        string username;
        string UserPath;
        string transactionPath;
        string transactionPath_enc;
        string userFilePath;
        string pwdFilePath;

    public:
        FileManager(string);
        ~FileManager();
        
        User getUser();
        void insertTransaction(string, string);
        void receiveTransaction(string, string);
        Transaction* getTransactions(string, int t, int&);
        static string getTime();
        string getUserFilePath();
        string getTransactionPath();
        string getPwdPath();
        
        void updateBalance(string, string);
        void updateCounter(string);
        void resetCounter(string);
};

#endif