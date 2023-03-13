#ifndef _TLSTEST_SERVER
#define _TLSTEST_SERVER
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "../common/link.h"

class T_Server{
private:
    BIO* out_bio;
    BIO* in_bio;
    SSL* ssl;
    char* socket_buf;
    char* ssl_buf;
    int traffic_in();
    int traffic_out();
    bool is_handshaking;
    Link* link;
public:
    T_Server(SSL_CTX* ctx);
    ~T_Server();

    void handshake();
    void show_certs();
    int server_send(char* buf, int len);
    int plain_send(const char* buf, int len);
    int server_recv(char* buf); //buf here is allocated by socket_buf
    int get_encrypted_len();
    char* get_encrypted_text();
    void set_tcplink_fd(int fd);
    void set_fakelink(BIO* peer_out, BIO* peer_in, char* data);
};

#endif