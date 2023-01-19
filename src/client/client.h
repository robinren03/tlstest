#ifndef _TLSTEST_CLIENT
#define _TLSTEST_CLIENT
#include <openssl/ssl.h>
#include <openssl/bio.h>

class T_Client{
private:
    BIO* out_bio;
    BIO* in_bio;
    SSL* ssl;
    char* socket_buf;
    char* ssl_buf;
    int fd; //the socket file number
    int traffic_in();
    int traffic_out();
    bool is_handshaking;
public:
    T_Client(SSL_CTX* ctx, int _fd);
    ~T_Client();

    void handshake();
    void shutdown();
    int client_send(char* buf, int len);
    int client_recv(char* buf); //buf here is allocated by socket_buf
    char* get_encrypted_text();
};

#endif