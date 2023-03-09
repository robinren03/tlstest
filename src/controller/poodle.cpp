#include "poodle.h"
#include "../common/conf.h"
#include "../common/utils.h"
PoodleDecrypter::PoodleDecrypter(int max_len, int _block_size, T_Controller* _ctrl):max_len(max_len), block_size(_block_size), ctrl(_ctrl){

};


int PoodleDecrypter::get_len(const std::string secret){
    char buf[MAXBUF];
    for (int i=0; i<block_size; i++)
        buf[i] = 'A';
    strcpy(buf + block_size, secret.c_str());
    ctrl->send_client_instruction(T_Instr::ENCRYPTED_MESSAGE_TO_PEER, buf, secret.length() + block_size);
    ctrl->send_server_instruction(T_Instr::RECEIVED_PLAIN_TO_ME, nullptr, 0);
    int prev_len;
    ctrl->recv_server_message((char*)&prev_len);
    for (int i = 1; i <= block_size; i++)
    {
        ctrl->send_client_instruction(T_Instr::ENCRYPTED_MESSAGE_TO_PEER, buf+i, secret.length() + block_size - i);
        ctrl->send_server_instruction(T_Instr::RECEIVED_PLAIN_TO_ME, nullptr, 0);
        int len;
        ctrl->recv_server_message((char*)&len);
        if (len < prev_len) return i;   
    }
    return -1;
}

bool PoodleDecrypter::run(const std::string secret, const std::string known_head) {
    int secret_len = get_len(secret);
    int known_len = known_head.length();
    if (known_len % block_size >= secret_len) secret_len += block_size;
    secret_len += (known_len / block_size) * block_size;
    char buf[MAXBUF];
    int two_block = block_size << 1;
    for (int i=0; i<two_block; i++)
        buf[i] = 'A';
    strcpy(buf + two_block, secret.c_str());
    for (int i=two_block + secret_len; i<secret_len+block_size*3; i++)
        buf[i] = 'B';
    int pad =  block_size - 1 - known_len % block_size;
    for (int i=known_len; i<=secret_len; i++)
    {
        int len = round_up(pad + secret_len, block_size);
        while (true) {
            ctrl->send_client_instruction(T_Instr::ENCRYPTED_MESSAGE_TO_PEER, buf + (block_size - pad), len);
            ctrl->send_server_instruction(T_Instr::RECEIVED_PLAIN_TO_ME, nullptr, 0);
            int recv_len = ctrl->recv_server_message(last_recv);
            int block_to_be_changed = 1 + (i + pad) / block_size; 
            int relative_place = i + block_size + pad;
            char* recv_ptr = last_recv + (recv_len - block_size - 1);
            char* buf_ptr = buf + i + block_size + 1;
            for (int i=0; i< block_size; i++)
            {
                (*recv_ptr) = (*buf_ptr);
                buf_ptr ++;
                recv_ptr ++;
            }
            
            ctrl->send_client_instruction(T_Instr::PLAIN_MESSAGE_TO_PEER, buf + (block_size -pad), pad + block_size + secret_len);
            ctrl->send_server_instruction(T_Instr::RECEIVED_CHECK_VALID, nullptr, 0);
            bool isValid;
            ctrl->recv_server_message((char*)&isValid);
            if (isValid) {
                char real_ch = last_recv[i+pad] ^ last_recv[recv_len - block_size - 1] ^ (block_size - 1);
                printf("%c", real_ch);
                if (real_ch != secret[i]) return false;
                pad--;
                break;
            }
        }
    }
    return true;
}

