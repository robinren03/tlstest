#include "server.h"
#include <sys/socket.h>
#include "../common/conf.h"

void krx_ssl_server_info_callback(const SSL* ssl, int where, int ret) {

  if(ret == 0) {
    printf("-- krx_ssl_info_callback: error occured.\n");
    return;
  }
 
  SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP", "server");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START", "server");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE", "server");

}

T_Server::T_Server(SSL_CTX* ctx, int _fd):fd(_fd){
    socket_buf = new char[MAXBUF];
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
    delete[] socket_buf;
    delete[] ssl_buf;
}

int T_Server::traffic_in(){
    printf("Traffic in\n");
    int len = recv(fd, socket_buf, sizeof(socket_buf), 0);
    int written = BIO_write(in_bio, socket_buf, len);
    printf("Len is %d, written is %d, write is %s\n", len, written, socket_buf);
    if(written > 0) {
        if(!SSL_is_init_finished(ssl)) {
            SSL_do_handshake(ssl);
        }
  }
  return written;
}

int T_Server::traffic_out() {
    printf("Traffic out\n");
    int pending = BIO_ctrl_pending(out_bio); // Make sure the data is fine, for use of handshaking only
    while (pending == 0) pending = BIO_ctrl_pending(out_bio);
    int sock_len = BIO_read(out_bio, socket_buf, sizeof(socket_buf));
    printf("sock_len is %d, write is %s\n", sock_len, socket_buf);
    if (sock_len > 0) return send(fd, socket_buf, sock_len, 0);
}

void T_Server::handshake(){
    traffic_in();
    traffic_out();
    traffic_in();
    traffic_out(); 
}

int T_Server::server_send(char* buf, int len){
    SSL_write(ssl, buf, len);
    return traffic_out();
}

int T_Server::server_recv(char* buf){
    traffic_in();
    return SSL_read(ssl, buf, sizeof(buf));
}

char* T_Server::get_encrypted_text(){
    return socket_buf;
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

