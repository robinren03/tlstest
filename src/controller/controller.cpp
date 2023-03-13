#include "controller.h"
#include "../common/conf.h"
#include <sys/socket.h>

T_Controller::T_Controller(CtrlLink* _sev_lk, CtrlLink* _cli_lk):sev_lk(_sev_lk), cli_lk(_cli_lk){
}

void T_Controller::send_client_instruction(T_Instr ins, const char* buf, int len){
    cli_lk->link_send((char*)&ins, sizeof(T_Instr));
    if (len > 0) cli_lk->link_send(buf, len);  
}

void T_Controller::send_server_instruction(T_Instr ins, const char* buf, int len){
    sev_lk->link_send((char*)&ins, sizeof(T_Instr));
    if (len > 0) sev_lk->link_send(buf, len); 
}

int T_Controller::recv_client_message(char* buf){
    return cli_lk->link_recv(buf);
}

int T_Controller::recv_server_message(char* buf){
    return cli_lk->link_recv(buf);
}