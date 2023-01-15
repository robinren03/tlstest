#ifndef _TLSTEST_BEAST
#define _TLSTEST_BEAST
#include <iostream>

class BeastDecrypter{
private:
    char* buf;
    char* recv;
    int max_len;
public:
    BeastDecrypter(int max_len);
    
    ~BeastDecrypter(){
        free(buf);
        free(recv);
    }

    void send_malicious_message(char* buf, int len, char* recv); //get encrypt
       
    int decrypt_method(char* find);  

    void padding(char* buf);
    void run(const std::string secret, const std::string known_head);
}

#endif
