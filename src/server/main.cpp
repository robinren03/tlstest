#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl2.h>
#include "server.h"
#include "../common/instruction.h"

#define MAXBUF 1024

int main(int argc, char **argv) {
    int sockfd, new_fd;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    unsigned int myport, lisnum;
    char buf[MAXBUF + 1];
    SSL_CTX *ctx;

    if (argv[1])
        myport = atoi(argv[1]);
    else
        myport = 7838;

    if (argv[2])
        lisnum = atoi(argv[2]);
    else
        lisnum = 2;

    /* SSL 库初始化 */
    SSL_library_init();
    /* 载入所有 SSL 错误消息 */
    SSL_load_error_strings();
    /* 以 SSL V2 和 V3 标准兼容方式产生一个 SSL_CTX ，即 SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_server_method());
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 单独表示 V2 或 V3标准 */
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

    /* 开启一个 socket 监听 */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    } else
        printf("socket created\n");

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(myport);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr))
            == -1) {
        perror("bind");
        exit(1);
    } else
        printf("binded\n");

    if (listen(sockfd, lisnum) == -1) {
        perror("listen");
        exit(1);
    } else
        printf("begin listen\n");


    while (1) {
        len = sizeof(struct sockaddr);
        /* 等待客户端连上来 */
        if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len))
                == -1) {
            perror("accept");
            exit(errno);
        } else
            printf("server: got connection from %s, port %d, socket %d\n",
                    inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port),
                    new_fd);
        /* 基于 ctx 产生一个新的 SSL 
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_fd);
        if (SSL_accept(ssl) == -1) {
            perror("accept");
            close(new_fd);
            break;
        }
        */
        T_Server* sev = new T_Server(ctx, new_fd);
        sev->show_certs();

        int ctrl_fd;
        if ((ctrl_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket");
            exit(errno);
        }
        printf("socket created\n");
        struct sockaddr_in dest;

        bzero(&dest, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(atoi(argv[6]));
        if (inet_aton(argv[5], (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
            perror(argv[5]);
            exit(errno);
        }
        printf("controller address created\n");

        /* 连接服务器 */
        if (connect(ctrl_fd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
            perror("Connect ");
            exit(errno);
        }
        printf("controller connected\n");

        /* 开始处理每个新连接上的数据收发 */
        bzero(buf, MAXBUF + 1);
        strcpy(buf, "server->client");
        sev->server_send(buf, strlen(buf));

        bzero(buf, MAXBUF + 1);
        /* 接收客户端的消息 */
        len = sev->server_recv(buf);
        if (len > 0)
            printf("接收消息成功:'%s'，共%d个字节的数据\n", buf, len);
        else
            printf("消息接收失败！错误代码是%d，错误信息是'%s'\n",
            errno, strerror(errno));
        
        bool cont = true;
        while(cont){
            T_Instr inst;
            int len = recv(ctrl_fd, &inst, sizeof(T_Instr), 1);
            if (len<=0) break;
            switch (inst){
                case T_Instr::ENCRYPTED_MESSAGE_TO_PEER:{
                    int len = recv(ctrl_fd, buf, MAXBUF, 0);
                    sev->server_send(buf, len);
                    break;
                }
                case T_Instr::SHUTDOWN_CONNECTION: {
                    cont = false;
                    break;
                }

                default: break;
            }
        }
        delete sev;
        close(new_fd);
        close(ctrl_fd);
    }
    /* 关闭监听的 socket */
    close(sockfd);
    /* 释放 CTX */
    SSL_CTX_free(ctx);
    return 0;
}