#ifndef _TLSTEST_SIMULATOR
#define _TLSTEST_SIMULATOR
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include "link.h"

class T_Simulator{
protected:
    SSL* ssl;
    Link* link;
public:
    BIO *out_bio, *in_bio;
    virtual int send(const char* buf, int len) = 0;
    virtual int recv(char* buf) = 0; //buf here is allocated by socket_buf
    virtual int plain_send(const char* buf, int len) = 0;
    virtual char* get_encrypted_text() = 0;
    virtual int get_encrypted_len() = 0;
};

#endif