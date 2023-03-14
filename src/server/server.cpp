#include "server.h"
#include <sys/socket.h>
#include "../common/conf.h"
#include <openssl/err.h>

void krx_ssl_server_info_callback(const SSL* ssl, int where, int ret) {

  if(ret == 0) {
    printf("-- krx_ssl_info_callback: error occured.\n");
    ERR_print_errors_fp(stdout);
    return;
  }
 
  SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP", "server");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START", "server");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE", "server");

}

T_Server::T_Server(SSL_CTX* ctx){
    ssl_buf = new char[MAXBUF];
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        puts("Can not create new ssl");
        exit(-1);
    }

    SSL_set_info_callback(ssl, krx_ssl_server_info_callback);
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

T_Server::~T_Server(){
    SSL_shutdown(ssl);
    SSL_free(ssl);
    delete[] ssl_buf;
}

int T_Server::traffic_in(){
    int written = link->link_recv();
    if(written > 0) {
            if(!SSL_is_init_finished(ssl)) SSL_do_handshake(ssl);
    }
    return written;
}

int T_Server::traffic_out() {
    return link->link_send();
}

void T_Server::handshake(){
    traffic_in();
    traffic_out();
    traffic_in();
    traffic_out(); 
    printf("Cipher mode is %s\n", SSL_get_cipher_name(ssl));
}

int T_Server::send(const char* buf, int len){
    SSL_write(ssl, buf, len);
    return traffic_out();
}

int T_Server::plain_send(const char* buf, int len){
    BIO_write(out_bio,  buf, len);
    return link -> link_send();
}

int T_Server::recv(char* buf){
    traffic_in();
    return SSL_read(ssl, buf, MAXBUF);
}

char* T_Server::get_encrypted_text(){
    return socket_buf + 5;
}

int T_Server::get_encrypted_len(){
    return link->get_data_len() - 5;
}

void T_Server::show_certs()
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    // SSL_get_verify_result()是重点，SSL_CTX_set_verify()只是配置启不启用并没有执行认证，调用该函数才会真证进行证书认证
    // 如果验证不通过，那么程序抛出异常中止连接
    if(SSL_get_verify_result(ssl) == X509_V_OK){
        printf("证书验证通过\n");
    }
    if (cert != NULL) {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    } else
        printf("无证书信息！\n");
}

void T_Server::set_tcplink_fd(int fd){
    link = new TCPDirectLink(out_bio, in_bio, fd);
    socket_buf = link->get_data_ptr();
}

void T_Server::set_fakelink(BIO* peer_out, BIO* peer_in, char* data){
    socket_buf = data;
    link = new FakeDirectLink(out_bio, in_bio, peer_out, peer_in, data);
}
