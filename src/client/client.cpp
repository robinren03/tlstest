#include "client.h"
#include "../common/conf.h"
#include "../common/utils.h"
#include <openssl/err.h>
#include <sys/socket.h>

void krx_ssl_client_info_callback(const SSL* ssl, int where, int ret) {

  if(ret == 0) {
    printf("-- krx_ssl_info_callback: error occured.\n");
    ERR_print_errors_fp(stdout);
    return;
  }
 
  SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP", "client");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START", "client");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE", "client");

}

T_Client::T_Client(SSL_CTX* ctx){
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
    delete[] ssl_buf;
}

int T_Client::traffic_in(){
    if (!link) {
        puts("Create the link first!");
        return -1;
    }
    int written = link->link_recv();
    if(written > 0) {
            if(!SSL_is_init_finished(ssl)) SSL_do_handshake(ssl);
    }
    return written;
}

int T_Client::traffic_out() {
    if (!link) {
        puts("Create the link first!");
        return -1;
    }
    return link->link_send();
}

void T_Client::handshake(){ //handshake without interception
    SSL_do_handshake(ssl);
    traffic_out();
    traffic_in();
    traffic_out();
    traffic_in();
    printf("Cipher mode is %s\n", SSL_get_cipher_name(ssl));
}

int T_Client::send(const char* buf, int len){
    SSL_write(ssl, buf, len);
    return traffic_out();
}

int T_Client::plain_send(const char* buf, int len){
    // memcpy(socket_buf, buf, len);
    BIO_write(out_bio,  buf, len);
    return link -> link_send();
}

int T_Client::recv(char* buf){
    traffic_in();
    return SSL_read(ssl, buf, MAXBUF);
}

char* T_Client::get_encrypted_text(){
    return socket_buf + 5;
}

int T_Client::get_encrypted_len(){
    return link->get_data_len() - 5;
}

void T_Client::set_tcplink_fd(int fd){
    link = new TCPDirectLink(out_bio, in_bio, fd);
    socket_buf = link->get_data_ptr();
}

void T_Client::set_fakelink(BIO* peer_out, BIO* peer_in, char* data){
    socket_buf = data;
    link = new FakeDirectLink(out_bio, in_bio, peer_out, peer_in, data);
}