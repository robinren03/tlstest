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
#include <openssl/ssl2.h>
#include <openssl/err.h>
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
        printf("参数格式错误！正确用法如下：\n\t\t%s IP地址 端口\n\t比如:\t%s 127.0.0.1 80\n此程序用来从某个"
             "IP 地址的服务器某个端口接收最多 MAXBUF 个字节的消息",
             argv[0], argv[0]);
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

    int valid = SSL_CTX_set_cipher_list(ctx, SSL2_TXT_DES_64_CBC_WITH_MD5);
    if (valid) {
        ERR_print_errors_fp(stdout);
    }
    // 双向验证
    // SSL_VERIFY_PEER---要求对证书进行认证，没有证书也会放行
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT---要求客户端需要提供证书，但验证发现单独使用没有证书也会放行
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    // 设置信任根证书
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt",NULL)<=0){
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(ctx, argv[3], SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, argv[4], SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 检查用户私钥是否正确 */
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

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