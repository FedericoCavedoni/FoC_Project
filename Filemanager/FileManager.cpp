#include "FileManager.hpp"

void fileCopy(string source, string dest){
    ifstream inFile(source);
    ofstream outFile(dest); // File outoraneo

    if (!inFile.is_open() || !outFile.is_open()) {
        cerr << "Unable to open the file(s)" << endl;
        return;
    }

    string fileContents;
    string currentLine;
    while (getline(inFile, currentLine)) {
        fileContents += currentLine + "\n";
    }
    outFile << fileContents;

    inFile.close();
    outFile.close();
}

void insertAtTheStart(string transactionPath, string line) {
    string temp = "Util/temp.txt";
    ifstream inFile(transactionPath);
    ofstream tempFile(temp); // File temporaneo

    if (!inFile.is_open() || !tempFile.is_open()) {
        cerr << "Unable to open the file(s)" << endl;
        return;
    }

    // Scrivi la nuova riga all'inizio del file temporaneo
    tempFile << line << endl;

    // Copia il contenuto del file originale dopo la nuova riga nel file temporaneo
    string fileContents;
    string currentLine;
    while (getline(inFile, currentLine)) {
        fileContents += currentLine + "\n";
    }
    tempFile << fileContents;

    inFile.close();
    tempFile.close();

    fileCopy(temp, transactionPath);

    if (remove(temp.c_str()) != 0) {
        cerr << "Impossibile rimuovere il file." << endl;
        return;
    }
    
}

FileManager::FileManager(string username){
    this->username = username;
    this->UserPath = "Users/" + this->username + "/";

    this->transactionPath = this->UserPath + "transactions.txt";

    this->userFilePath = this->UserPath + this->username + ".txt";
    this->pwdFilePath = this->UserPath + "password.txt";
}
FileManager::~FileManager(){}

string FileManager::getUserFilePath(){
    return this->userFilePath;
}

string FileManager::getTransactionPath(){
    return this->transactionPath;
}
string FileManager::getPwdPath(){
    return this->pwdFilePath;
}

string FileManager::getTime(){
    time_t now = time(nullptr);

    // Convertiamo l'orario corrente in una struttura tm per ottenere parti specifiche (anno, mese, giorno, ora, minuti, secondi)
    tm* timeinfo = localtime(&now);

    // Convertiamo il timestamp in una stringa formattata
    stringstream ss;
    ss << put_time(timeinfo, "%Y-%m-%d %H:%M:%S");
    string timestamp = ss.str();

    return timestamp;
} 

User FileManager::getUser(){
    ifstream file(userFilePath);
    string line;
    string temp;
    string pwd;
    User user = User();
    int i=0; 

    if (!filesystem::exists(userFilePath)) {
        return user;
    }

    if (!file.is_open()) {
        cerr << "Unable to open the file" << endl;
        return user;
    }

    if(getline(file, line)){ //formato id,username,password,balance
        istringstream ss(line);
        char delimiter = ',';
        while(getline(ss, temp, delimiter)){

            if(i>4)
                break;
                
            switch(i){
                case 0:
                    user.setId(stoi(temp));
                    break;
                case 1:
                    user.setUsername(temp);
                    break;
                case 2:
                    user.setBalance(temp);
                    break;
                case 3:
                    user.setSalt(temp);
                    break;
                case 4:
                    user.setCounter(stoi(temp));
                    break;
            }

            i++;
        }
    }

    file.close();

    ifstream file1(pwdFilePath);
    char c;

    if (!file1.is_open()) {
        cerr << "Error!" << endl;
        return user;
    }

    while (file1.get(c)) {
        pwd += c;
    }

    // Chiudi il file1
    file1.close();
    
    user.setPassword(pwd);

    return user;
}

void FileManager::insertTransaction(string dest, string amount){

    User user = User();
    Transaction trans = Transaction();
    user = getUser();
    string timestamp = getTime();

    string line = to_string(trans.getId()) + ',' + user.getUsername() + ',' + dest + ',' + amount + ',' + timestamp + ',';//formato id, Username, trans (dest:amount:timestamp)

    insertAtTheStart(transactionPath, line);
}

void FileManager::receiveTransaction(string source, string amount){
    User user = User();
    Transaction trans = Transaction(false);
    user = getUser();
    string timestamp = getTime();

    string line = to_string(trans.getId()) + ',' + source + ',' + user.getUsername() + ',' + amount + ',' + timestamp + ',';//formato id, Username, trans (dest:amount:timestamp)

    insertAtTheStart(transactionPath, line);
}


Transaction* FileManager::getTransactions(string, int t, int &i){

    ifstream file(transactionPath); 
    Transaction *transArray = new Transaction[t];
    i=0;
    int j=0;

    if (!filesystem::exists(transactionPath)) {
        return transArray;
    }

    if (!file.is_open()) {
        cerr << "Unable to open the file" << endl;
        return transArray;
    }

    string line;
    string temp;

    while(getline(file, line)) { //formato id,src,dest,Transaction
        Transaction trans = Transaction(false); 
        line.resize(line.size()-1);
        if(strcmp(line.c_str(), "") == 0 || strcmp(line.c_str(), " ") == 0){
            break;
        }

        istringstream ss(line);
        char delimiter = ',';
        while(getline(ss, temp, delimiter)){

            if(j>4)
                break;

            switch(j){
                case 0:
                    try{
                        trans.setId(stoi(temp));
                    } catch(exception e){
                        i--;
                        break;
                    }
                    break;
                case 1:
                    trans.setSrc(temp);
                    break;
                case 2:
                    trans.setDest(temp);
                    break;
                case 3:
                    trans.setAmount(temp);
                    break;
                case 4:
                    trans.setTimestamp(temp);
                    break;
            }

            j++;
        }

        transArray[i] = trans;
        i++;
        j=0;

        if(i>=t){
            break;
        }
    }

    file.close();
    return transArray;
}

void FileManager::updateBalance(string username, string balance){
    FileManager fm = FileManager(username);
    User user = fm.getUser();

    user.setBalance(balance);

    ofstream file(fm.getUserFilePath());
    string line = to_string(user.getId()) + ',' + user.getUsername() + ',' + balance +',' + user.getSalt() + ','+ to_string(user.getCounter()) +',';
    file<<line;
}

void FileManager::updateCounter(string username){
    FileManager fm = FileManager(username);
    User user = fm.getUser();

    ofstream file(fm.getUserFilePath());
    uint32_t c = user.getCounter() + 1;
    string line = to_string(user.getId()) + ',' + user.getUsername() + ',' + user.getBalance() +',' + user.getSalt() + ',' + to_string(c) + ',';
    file<<line;
}

void FileManager::resetCounter(string username){
    FileManager fm = FileManager(username);
    User user = fm.getUser();

    ofstream file(fm.getUserFilePath());
    string line = to_string(user.getId()) + ',' + user.getUsername() + ',' + user.getBalance() +',' + user.getSalt() + ',' + to_string(0) + ',';
    file<<line;
}