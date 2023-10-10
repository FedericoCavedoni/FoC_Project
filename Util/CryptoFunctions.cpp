#include "cryptoHeader.hpp"

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

EVP_PKEY *generate_params(){

    EVP_PKEY *dh_params = nullptr;
    EVP_PKEY_CTX *dh_gen_ctx = nullptr;
    EVP_PKEY *dh_key = nullptr;

    int ret;

    // Allocate p and g
    dh_params = EVP_PKEY_new();
    if (!dh_params){
        cerr << "ERR: Couldn't generate new dh params!" << endl;
        return nullptr;
    }

    // Set default dh parameters for p & g
    DH *default_params = DH_get_2048_224();
    ret = EVP_PKEY_set1_DH(dh_params, default_params);

    // Delete p & g
    DH_free(default_params);

    if (ret != 1){
        EVP_PKEY_free(dh_params);
        cerr << "ERR: Couldn't load default params!" << endl;
        return nullptr;
    }

    // a or b
    dh_gen_ctx = EVP_PKEY_CTX_new(dh_params, nullptr);
    if (!dh_gen_ctx){
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(dh_gen_ctx);
        cerr << "ERR: Couldn't load define dh context!" << endl;
        return nullptr;
    }

    ret = EVP_PKEY_keygen_init(dh_gen_ctx);
    if (ret != 1){
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(dh_gen_ctx);
        cerr << "ERR: Couldn't dh keygen init!" << endl;
        return nullptr;
    }

    ret = EVP_PKEY_keygen(dh_gen_ctx, &dh_key);
    if (ret != 1)
    {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(dh_gen_ctx);
        cerr << "ERR: Couldn't dh keygen!" << endl;
        return nullptr;
    }

    EVP_PKEY_CTX_free(dh_gen_ctx);
    EVP_PKEY_free(dh_params);

    return dh_key;
}

void generate_secrets(EVP_PKEY* private_key, EVP_PKEY* peer_ephemeral_key, vector<uint8_t>& shared_secret, size_t& shared_secret_size) {

    EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!derive_ctx){
        cerr << "Errore: " << errno << endl;
        throw runtime_error("Failed to create derive context.");
    }

    if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
        EVP_PKEY_CTX_free(derive_ctx);
        throw runtime_error("Failed to initialize derive context.");
    }

    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_ephemeral_key) <= 0) {
        EVP_PKEY_CTX_free(derive_ctx);
        throw runtime_error("Failed to set peer ephemeral keys in the context.");
    }

    EVP_PKEY_derive(derive_ctx, NULL, &shared_secret_size);
    shared_secret.resize(int(shared_secret_size));
    if (EVP_PKEY_derive(derive_ctx, shared_secret.data(), &shared_secret_size) <= 0) {
        EVP_PKEY_CTX_free(derive_ctx);
        throw runtime_error("Failed to generate shared secret.");
    }
    
    EVP_PKEY_CTX_free(derive_ctx);
}

EVP_PKEY* read_server_private_key(){
    string privPath = "Server/keys/private_key.pem";

    FILE *file = fopen(privPath.c_str(), "r");
    if (!file) {
        return 0;
    } 

    EVP_PKEY *privk = EVP_PKEY_new();
    privk =  PEM_read_PrivateKey(file, NULL, NULL, (void *)"password");
    fclose(file);

    return privk;
}

EVP_PKEY* read_server_public_key(){
    string pubPath = "Server/keys/public_key.pem";

    FILE *file = fopen(pubPath.c_str(), "r");
    if (!file) {
        return 0;
    } 

    EVP_PKEY *pubk = EVP_PKEY_new();
    pubk =  PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);

    return pubk;
}

EVP_PKEY* read_public_key(string user){
    string pubPath = user+"_keys/public_key.pem";
    

    FILE *file = fopen(pubPath.c_str(), "r");
    if (!file) {
        return 0;
    } 

    EVP_PKEY *pubk = EVP_PKEY_new();
    pubk =  PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);

    return pubk;
}


EVP_PKEY* read_private_key(string user){
    string privPath = user+"_keys/private_key.pem";
    char *pwd = getpass("Enter PEM pass phrase: ");

    FILE *file = fopen(privPath.c_str(), "r");
    if (!file) {
        return 0;
    } 

    EVP_PKEY *privk = EVP_PKEY_new();
    privk =  PEM_read_PrivateKey(file, NULL, NULL, pwd);
    
    fclose(file);

    return privk;
}


vector<unsigned char> sign_message(const vector<unsigned char>& buffer, EVP_PKEY* private_key) {
    if (!private_key)
        throw runtime_error("Private key not loaded.");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY* privkey = private_key;

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        throw runtime_error("Failed to initialize signing context.");
    }

    if (EVP_DigestSignUpdate(ctx, buffer.data(), buffer.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        throw runtime_error("Failed to update signing context.");
    }

    size_t signatureLen;
    if (EVP_DigestSignFinal(ctx, nullptr, &signatureLen) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        throw runtime_error("Failed to determine signature length.");
    }

    vector<unsigned char> signature(signatureLen);
    if (EVP_DigestSignFinal(ctx, signature.data(), &signatureLen) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        throw runtime_error("Failed to sign the buffer.");
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(privkey);

    return signature;
}

bool verify_signature(const vector<unsigned char>& buffer, const vector<unsigned char>& signature, EVP_PKEY* public_key) {
    if (!public_key)
        throw runtime_error("Public key not loaded.");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY* pubkey = public_key;

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pubkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        throw runtime_error("Failed to initialize verification context.");
    }

    if (EVP_DigestVerifyUpdate(ctx, buffer.data(), buffer.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        throw runtime_error("Failed to update verification context.");
    }

    int result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);

    if (result == 1) {
        return true; // Signature verified successfully
    } else if (result == 0) {
        return false; // Signature verification failed
    } else {
        throw runtime_error("Error occurred during signature verification.");
    }
}

void cbc_encrypt(const vector<uint8_t>& input_buffer, vector<uint8_t>& output_buffer, vector<uint8_t>& iv, vector<uint8_t>& key){
    vector <uint8_t> plaintext;
    vector<uint8_t> ciphertext;
    EVP_CIPHER_CTX* ctx = nullptr; // Inizializza a nullptr
    uint32_t processed_bytes = 0;

    iv = generate_iv(); // Genera IV per la cifratura

    const long unsigned int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    plaintext.resize(input_buffer.size());
    std::copy(input_buffer.begin(), input_buffer.end(), plaintext.begin());

    if (plaintext.size() > INT_MAX - block_size)
        throw runtime_error("Overflow di intero (file troppo grande?).");

    if (!(ctx = EVP_CIPHER_CTX_new()))
        throw runtime_error("Impossibile creare EVP_CIPHER_CTX.");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data())) != 1)
        throw runtime_error("Inizializzazione cifratura fallita.");

    ciphertext.resize(plaintext.size() + block_size);

    int update_len = 0;
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()), &update_len, reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size())) != 1)
        throw runtime_error("Aggiornamento cifratura fallito.");

    processed_bytes += update_len;

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data() + processed_bytes), &final_len) != 1) {
        throw runtime_error("Finalizzazione cifratura fallita.");
    }

    processed_bytes += final_len;
    ciphertext.resize(processed_bytes); // Ridimensiona alla dimensione effettiva

    EVP_CIPHER_CTX_free(ctx); // Libera il contesto

    output_buffer = ciphertext; // Non c'è bisogno di copiare o ridurre
}


void cbc_decrypt(const vector<uint8_t>& input_buffer, vector<uint8_t>& output_buffer, const vector<uint8_t>& iv, vector<uint8_t>& key){
    vector<uint8_t> ciphertext;
    vector<uint8_t> plaintext;
    EVP_CIPHER_CTX* ctx = nullptr; // Inizializza a nullptr
    uint32_t processed_bytes = 0;

    ciphertext.resize(input_buffer.size());
    copy(input_buffer.begin(), input_buffer.end(), ciphertext.begin());

    if (iv.size() != EVP_CIPHER_iv_length(EVP_aes_256_cbc()))
        throw runtime_error("Lunghezza IV non valida.");

    plaintext.resize(ciphertext.size());


    if (key.empty() || ciphertext.empty())
        throw runtime_error("Chiave o ciphertext vuoti.");

    if (!(ctx = EVP_CIPHER_CTX_new()))
        throw runtime_error("Impossibile creare EVP_CIPHER_CTX.");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data())) != 1)
        throw runtime_error("Inizializzazione decifrazione fallita.");

    int update_len = 0;
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &update_len, reinterpret_cast<const unsigned char*>(ciphertext.data()), static_cast<int>(ciphertext.size())) != 1) {
        throw runtime_error("Aggiornamento decifrazione fallito.");
    }

    processed_bytes += update_len;

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data() + processed_bytes), &final_len) != 1) {
        auto error_code = ERR_get_error();
        cout << error_code << endl;

        char error_string[1024];
        ERR_error_string(error_code, error_string);

        cout << error_string << endl;

        ERR_print_errors_fp(stderr);

        if (error_code == EVP_R_BAD_DECRYPT)
            throw runtime_error("Decifrazione fallita: Errore di autenticazione o ciphertext manomesso.");
        else {
            throw runtime_error("Decifrazione fallita: Errore sconosciuto.");
        }
    }


    processed_bytes += final_len;
    plaintext.resize(processed_bytes); // Ridimensiona alla dimensione effettiva

    EVP_CIPHER_CTX_free(ctx); // Libera il contesto

    output_buffer = plaintext; // Non c'è bisogno di copiare o ridurre
}




// Verify if 2 digest SHA-256 are the same
void generateSHA(const unsigned char* input_buffer, size_t input_buffer_size, vector<uint8_t>& digest, unsigned int& digest_size) 
{
    digest.resize(EVP_MD_size(EVP_sha512()));
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx)
        throw runtime_error("Failed to create EVP_MD_CTX.");

    if (EVP_DigestInit(ctx, EVP_sha512()) != 1) 
    {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Failed to initialize digest.");
    }

    if (EVP_DigestUpdate(ctx, input_buffer, input_buffer_size) != 1) 
    {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Failed to update digest.");
    }

    if (EVP_DigestFinal(ctx, digest.data(), &digest_size) != 1) 
    {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Failed to finalize digest.");
    }

    EVP_MD_CTX_free(ctx);
}

bool verifySHA(const unsigned char* input_buffer, size_t input_buffer_size, const unsigned char* input_digest) 
{
    vector<uint8_t> generated_digest;
    unsigned int generated_digest_size = 0;
    
    try {
        generateSHA(input_buffer, input_buffer_size, generated_digest, generated_digest_size);
        return CRYPTO_memcmp(input_digest, generated_digest.data(), EVP_MD_size(EVP_sha256())) == 0;
    } catch (...) {
        throw;
    }
}

void generateHMAC(unsigned char* input_buffer, size_t input_buffer_size, vector<unsigned char>& digest, unsigned int& digest_size, vector<unsigned char> key) 
{    
    digest.resize(EVP_MD_size(EVP_sha256()));
    HMAC_CTX* ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, key.data(), HMAC_DIGEST_SIZE, EVP_sha256(), nullptr);
    HMAC_Update(ctx, input_buffer, input_buffer_size);
    HMAC_Final(ctx, digest.data(), &digest_size);    

    HMAC_CTX_free(ctx);
}

bool verifyHMAC(unsigned char* input_buffer, size_t input_buffer_size, vector<unsigned char>& input_digest, vector<unsigned char> key) 
{
    vector<unsigned char> generated_digest;
    unsigned int generated_digest_size = 0;

    generateHMAC(input_buffer, input_buffer_size, generated_digest, generated_digest_size, key);
    bool res = CRYPTO_memcmp(input_digest.data(), generated_digest.data(), EVP_MD_size(EVP_sha256())) == 0;

    return res;
}

vector<unsigned char> generate_iv() {
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    std::vector<unsigned char> iv(iv_len);

    int ret = RAND_bytes(iv.data(), iv_len);
    if (ret != 1) {
        // Handle the error, possibly by throwing an exception or returning an empty vector.
        throw std::runtime_error("Failed to generate IV");
    }

    return iv;
}

vector<uint8_t> serializeKey(EVP_PKEY* key) {

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        throw runtime_error("Failed to create BIO.");

    if (!PEM_write_bio_PUBKEY(bio, key)) {
        BIO_free(bio);
        throw runtime_error("Failed to write key in the BIO.");
    }

    int serialized_key_size = BIO_pending(bio);
    vector<uint8_t> serialized_key(serialized_key_size);

    if (serialized_key.empty()) {
        BIO_free(bio);
        throw runtime_error("Failed to allocate memory.");
    }

    if (BIO_read(bio, serialized_key.data(), serialized_key_size) != serialized_key_size) {
        BIO_free(bio);
        throw runtime_error("Failed to write the serialized key in the buffer.");
    }
    
    BIO_free(bio);
    return serialized_key;
}

EVP_PKEY* deserializeKey(uint8_t* serialized_key, int serialized_key_size) 
{
    BIO *bio = BIO_new_mem_buf(serialized_key, serialized_key_size);
    if (!bio)
        throw runtime_error("Failed to create the BIO");

    EVP_PKEY* deserialized_key = nullptr;
    deserialized_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (deserialized_key == nullptr) {        
        BIO_free(bio);
        throw runtime_error("Failed to read the deserialized key");
    }

    BIO_free(bio);
    return deserialized_key;
}

void addZeros(string& input, int targetLength){
    if (input.length() >= targetLength) {
        return;
    }

    int numZeros = targetLength - input.length();
    string result(numZeros, '0'); 
    input = result + input;
}

void addPKCS7Padding(vector<uint8_t>& data, size_t block_size) {
    unsigned int padding_length = block_size - (data.size() % block_size);
    for (size_t i = 0; i < padding_length; ++i) {
        data.push_back(static_cast<uint8_t>(padding_length));
    }

}

void removePKCS7Padding(vector<uint8_t>& data) {
    if (data.empty()) {
        throw runtime_error("Dati vuoti, impossibile rimuovere il padding.");
    }

    unsigned int padding_length = data[data.size()-1];
    if (padding_length >= data.size()) {
        throw runtime_error("Padding non valido.");
    }

    data.resize(data.size() - padding_length);
}

void encryptFile(const char *inputFile, const char *outputFile, const unsigned char *key, const unsigned char *iv) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    AES_KEY aesKey;
    AES_set_encrypt_key(key, KEY_SIZE, &aesKey);

    unsigned char inBuffer[10000];
    unsigned char outBuffer[10000];

    //AES_cbc_encrypt(iv, inBuffer, AES_BLOCK_SIZE, &aesKey, (unsigned char*)iv, AES_ENCRYPT);
    out.write(reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);

    in.read(reinterpret_cast<char*>(inBuffer), 10000);
    int bytesRead = in.gcount();
    vector<uint8_t> in_buf(inBuffer, inBuffer+bytesRead);
    int b = bytesRead + AES_BLOCK_SIZE - (bytesRead % AES_BLOCK_SIZE);
    addPKCS7Padding(in_buf, AES_BLOCK_SIZE);
    AES_cbc_encrypt(in_buf.data(), outBuffer, b, &aesKey, (unsigned char*)iv, AES_ENCRYPT);   
    vector<uint8_t> out_buf(outBuffer, outBuffer+b);
    out.write((char*)out_buf.data(), b);

    in.close();
    out.close();
}

// Funzione per decifrare un file utilizzando AES-256 in modalità CBC
void decryptFile(const char *inputFile, const char *outputFile, const unsigned char *key) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    AES_KEY aesKey;
    AES_set_decrypt_key(key, KEY_SIZE, &aesKey);

    unsigned char inBuffer[10000];
    unsigned char outBuffer[10000];

    unsigned char iv[AES_BLOCK_SIZE];
    in.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE); 

    in.read(reinterpret_cast<char*>(inBuffer), 10000);
    int bytesRead = in.gcount();
    AES_cbc_encrypt(inBuffer, outBuffer, bytesRead, &aesKey, (unsigned char*)iv, AES_DECRYPT);
    int paddingByte = outBuffer[bytesRead - 1];
    out.write(reinterpret_cast<char*>(outBuffer), bytesRead-paddingByte);

    in.close();
    out.close();
}

#pragma GCC diagnostic pop 