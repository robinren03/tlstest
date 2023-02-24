/*
This is a basic implementation of the BEAST attack discovered by TBD in 2010.
Our current implementation only support to discover the first block_size bits
of encrypted information while with a little more improvements, we can infer
more information through this.
*/
#ifndef _TLSTEST_POODLE
#define _TLSTEST_POODLE
#include <cstring>
#include <iostream>
#include "controller.h"

class PoodleDecrypter{
private:
    char* buf;
    char* ori_recv;
    char* first_r;
    char* last_recv;
    int max_len;
    const int block_size;
    T_Controller* ctrl;

public:
    PoodleDecrypter(int max_len, int _block_size, T_Controller* _ctrl);
    
    ~PoodleDecrypter(){
        free(buf);
        free(ori_recv);
        free(last_recv);
        free(first_r);
    }

    int send_malicious_message(const char* buf, int len, char* recv); //get encrypt
       
    int decrypt_method(char* find);  

    void padding(char* buf);
    
    int get_len(const std::string secret);
    
    bool run(const std::string secret, const std::string known_head);

};
#endif
