#ifndef _TLSTEST_CLIENT
#define _TLSTEST_CLIENT
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "../common/link.h"

class T_Client{
private:
    BIO* out_bio;
    BIO* in_bio;
    SSL* ssl;
    Link* link;
    char* socket_buf;
    char* ssl_buf;
    int traffic_in();
    int traffic_out();
    bool is_handshaking;
public:
    T_Client(SSL_CTX* ctx);
    ~T_Client();
    void set_tcplink_fd(int fd);
    void set_fakelink(BIO* peer_out, BIO* peer_in, char* data);
    void handshake();
    int client_send(char* buf, int len);
    int client_recv(char* buf); //buf here is allocated by socket_buf
    int plain_send(const char* buf, int len);
    char* get_encrypted_text();
    int get_encrypted_len();
};

#endif