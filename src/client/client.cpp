#include "client.h"
#include <sys/socket.h>
#include "conf.h"

T_Client::T_Client(SSL_CTX* ctx, int _fd):fd(_fd){
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        puts("Can not create new ssl");
        exit(-1);
    }
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
    SSL_set_accept_state(ssl);
}

T_Client::~T_Client(){
    SSL_shutdown(ssl);
    SSL_free(ssl);
    delete[] socket_buf;
    delete[] ssl_buf;
}

int T_Client::traffic_in(){
    if (fd >= 0) {
        int len = recv(fd, socket_buf, sizeof(socket_buf), 0);
        int written = BIO_write(in_bio, socket_buf, len);
        if(written > 0) {
            if(!SSL_is_init_finished(ssl)) SSL_do_handshake(ssl);
        }
        return written;
    }
    return -1;
}

int T_Client::traffic_out() {
    if (fd >= 0) {
        int pending = BIO_ctrl_pending(out_bio); // Make sure the data is fine, for use of handshaking only
        if(pending > 0) {
            int sock_len = BIO_read(out_bio, socket_buf, sizeof(socket_buf));
            if (sock_len > 0) return send(fd, socket_buf, sock_len, 0);
        } 
    }
    return -1;
}
void T_Client::handshake(){
    while(!SSL_is_init_finished(ssl)) {
        SSL_do_handshake(ssl);
        traffic_out();
        traffic_in();
        traffic_out();
        traffic_in();
        printf("One round of handshake finished\n");
    } 
}

int T_Client::client_send(char* buf, int len){
    SSL_write(ssl, buf, len);
    return traffic_out();
}

int T_Client::client_recv(char* buf){
    traffic_in();
    return SSL_read(ssl, buf, sizeof(buf));
}

char* T_Client::get_encrypted_text(){
    return socket_buf;
}

