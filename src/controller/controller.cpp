#include "controller.h"
#include <sys/socket.h>

T_Controller::T_Controller(int _server_fd, int _client_fd):server_fd(_server_fd), client_fd(_client_fd){

}

void T_Controller::send_client_instruction(T_Instr ins, const char* buf, int len){
    send(client_fd, &ins, sizeof(T_Instr), 1);
    send(client_fd, buf, len, 0);  
}

void T_Controller::send_server_instruction(T_Instr ins, const char* buf, int len){
    send(server_fd, &ins, sizeof(T_Instr), 1);
    send(server_fd, buf, len, 0); 
}

int T_Controller::recv_client_message(char* buf){
    return recv(client_fd, buf, sizeof(buf), 0);
}

int T_Controller::recv_server_message(char* buf){
    return recv(server_fd, buf, sizeof(buf), 0);
}