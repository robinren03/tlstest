#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include "client.h"
#include "../common/conf.h"
#include "../common/instruction.h"

void ShowCerts(SSL * ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
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

int main(int argc, char **argv)
{
    int sockfd, len;
    struct sockaddr_in dest;
    char buffer[MAXBUF + 1];
    SSL_CTX *ctx;

    if (argc != 5) {
        printf("wrong format of arguments, please follow the guidelines on README\n");
        exit(0);
    }

    /* SSL 库初始化，参看 ssl-server.c 代码 */
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    
    int valid = SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    if (valid != 1) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); 


    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        perror(argv[1]);
        exit(errno);
    }
    printf("address created\n");

    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");
    
    T_Client* cli = new T_Client(ctx, sockfd);
    cli->handshake();
    
    /* build a new ssl based on ctx
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }
    */

    int ctrl_fd;
    if ((ctrl_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[4]));
    if (inet_aton(argv[3], (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        perror(argv[3]);
        exit(errno);
    }
    printf("controller address created\n");

    /* 连接服务器 */
    if (connect(ctrl_fd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("controller connected\n");

    bzero(buffer, MAXBUF + 1);
    strcpy(buffer, "client");
    send(ctrl_fd, buffer, strlen(buffer), 0);

    /* 接收对方发过来的消息，最多接收 MAXBUF 个字节 */
    bzero(buffer, MAXBUF + 1);
    /* 接收服务器来的消息 */
    len = cli->client_recv(buffer);
    if (len > 0)
        printf("接收消息成功:'%s'，共%d个字节的数据\n",
               buffer, len);
    else {
        printf
            ("消息接收失败！错误代码是%d，错误信息是'%s'\n",
             errno, strerror(errno));
    }
    
    bzero(buffer, MAXBUF + 1);
    strcpy(buffer, "from client->server");
    /* 发消息给服务器 */
    cli->client_send(buffer, strlen(buffer));
    if (len < 0)
        printf
            ("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n",
             buffer, errno, strerror(errno));
    else
        printf("消息'%s'发送成功，共发送了%d个字节！\n",
               buffer, len);
    
    bool cont = true;
    while(cont){
        T_Instr inst;
        int len = recv(ctrl_fd, &inst, sizeof(T_Instr), 1);
        if (len<=0) break;
        switch (inst){
            case T_Instr::ENCRYPTED_MESSAGE_TO_PEER:{
                int len = recv(ctrl_fd, buffer, MAXBUF, 0);
                cli->client_send(buffer, len);
                break;
            }
            case T_Instr::SHUTDOWN_CONNECTION: {
                cont = false;
                break;
            }
            default: break;
        }
    }
    /* 关闭连接 */
    delete cli;
    close(sockfd);
    close(ctrl_fd);
    SSL_CTX_free(ctx);
    return 0;
}