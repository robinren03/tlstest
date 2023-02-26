#include "client.h"
#include <sys/socket.h>
#include "../common/conf.h"

void krx_ssl_client_info_callback(const SSL* ssl, int where, int ret) {

  if(ret == 0) {
    printf("-- krx_ssl_info_callback: error occured.\n");
    return;
  }
 
  SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP", "client");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START", "client");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE", "client");

}

T_Client::T_Client(SSL_CTX* ctx, int _fd):fd(_fd){
    socket_buf = new char[MAXBUF];
    ssl_buf = new char[MAXBUF];
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        puts("Can not create new ssl");
        exit(-1);
    }
    SSL_set_info_callback(ssl, krx_ssl_client_info_callback);
    out_bio = BIO_new(BIO_s_mem());
    in_bio = BIO_new(BIO_s_mem());
    if (out_bio == NULL) {
        puts("Can not create new out_bio");
        exit(-2);
    }
    if (in_bio == NULL) {
        puts("Can not create new in_bio");
        exit(-3);
    }
    BIO_set_mem_eof_return(out_bio, -1);
    BIO_set_mem_eof_return(in_bio, -1);
    SSL_set_bio(ssl, in_bio, out_bio);
    SSL_set_connect_state(ssl);
}

T_Client::~T_Client(){
    SSL_shutdown(ssl);
    SSL_free(ssl);
    delete[] socket_buf;
    delete[] ssl_buf;
}

int T_Client::traffic_in(){
    printf("Traffic in\n");
    int len = recv(fd, socket_buf, MAXBUF, 0);
    encrypted_len = len;
    int written = BIO_write(in_bio, socket_buf, len);
    printf("Len is %d, written is %d, write is %s\n", len, written, socket_buf);
    if(written > 0) {
            if(!SSL_is_init_finished(ssl)) SSL_do_handshake(ssl);
    }
    return written;
}

int T_Client::traffic_out() {
    printf("Traffic out\n");
    int pending = BIO_ctrl_pending(out_bio); // Make sure the data is fine, for use of handshaking only
    if(pending > 0) {
        int sock_len = BIO_read(out_bio, socket_buf, MAXBUF);
        encrypted_len = sock_len;
        printf("pending is %d, sock_len is %d, write is %s\n", pending, sock_len, socket_buf);
        if (sock_len > 0) return send(fd, socket_buf, sock_len, 0);
    } 
    return -1;
}

void T_Client::handshake(){ //handshake without interception
    SSL_do_handshake(ssl);
    traffic_out();
    traffic_in();
    traffic_out();
    traffic_in();
    printf("Cipher mode is %s\n", SSL_get_cipher_name(ssl));
}

int T_Client::client_send(char* buf, int len){
    SSL_write(ssl, buf, len);
    return traffic_out();
}

int T_Client::plain_send(char* buf, int len){
    return send(fd, socket_buf, len, 0);
}

int T_Client::client_recv(char* buf){
    traffic_in();
    return SSL_read(ssl, buf, MAXBUF);
}

char* T_Client::get_encrypted_text(){
    return socket_buf + 5;
}

int T_Client::get_encrypted_len(){
    return encrypted_len - 5;
}

