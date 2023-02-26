#ifndef _TLSTEST_SERVER
#define _TLSTEST_SERVER
#include <openssl/ssl.h>
#include <openssl/bio.h>

class T_Server{
private:
    BIO* out_bio;
    BIO* in_bio;
    SSL* ssl;
    char* socket_buf;
    char* ssl_buf;
    int encrypted_len;
    int fd; //the socket file number
    int traffic_in();
    int traffic_out();
    bool is_handshaking;
public:
    T_Server(SSL_CTX* ctx, int _fd);
    ~T_Server();

    void handshake();
    void show_certs();
    int server_send(char* buf, int len);
    int plain_send(char* buf, int len);
    int server_recv(char* buf); //buf here is allocated by socket_buf
    int get_encrypted_len();
    char* get_encrypted_text();
};

#endif