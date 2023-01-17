#ifndef _TLSTEST_BEAST
#define _TLSTEST_BEAST
#include <cstring>
#include <iostream>

class BeastDecrypter{
private:
    char* buf;
    char* recv;
    int max_len;
    const int block_size = 32;
public:
    BeastDecrypter(int max_len, int _block_size);
    
    ~BeastDecrypter(){
        free(buf);
        free(recv);
    }

    void send_malicious_message(char* buf, int len, char* recv); //get encrypt
       
    int decrypt_method(char* find);  

    void padding(char* buf);
    
    void run(const std::string secret, const std::string known_head);
};

#endif
