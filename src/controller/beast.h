/*
This is a basic implementation of the BEAST attack discovered by TBD in 2010.
Our current implementation only support to discover the first block_size bits
of encrypted information while with a little more improvements, we can infer
more information through this.
*/
#ifndef _TLSTEST_BEAST
#define _TLSTEST_BEAST
#include <cstring>
#include <iostream>
#include "controller.h"

class BeastDecrypter{
private:
    char* buf;
    char* ori_recv;
    char* first_r;
    char* last_recv;
    int max_len;
    const int block_size = 32;
    T_Controller* ctrl;

public:
    BeastDecrypter(int max_len, int _block_size, T_Controller* _ctrl);
    
    ~BeastDecrypter(){
        free(buf);
        free(ori_recv);
        free(last_recv);
        free(first_r);
    }

    void send_malicious_message(const char* buf, int len, char* recv); //get encrypt
       
    int decrypt_method(char* find);  

    void padding(char* buf);
    
    bool run(const std::string secret, const std::string known_head);

    void xor_block(const char* a, const char* b, const char* c, char* buf);
};

#endif
