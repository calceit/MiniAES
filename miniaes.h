#ifndef MINIAES_H
#define MINIAES_H
#include <cstdint>
#include <string>
class MiniAES {
private:
    static const uint8_t SBOX[16];
    static const uint8_t INV_SBOX[16];
    static const uint8_t GF_MUL[16][16];
    static const uint8_t RCON[3];
    uint16_t roundKeys[3];
    static uint8_t getNibble(uint16_t block, int position);
    static uint16_t setNibble(uint16_t block, int position, uint8_t value);
    static uint16_t nibbleSub(uint16_t block);
    static uint16_t invNibbleSub(uint16_t block);
    static uint16_t shiftRow(uint16_t block);
    static uint16_t mixColumn(uint16_t block);
    static uint16_t keyAddition(uint16_t block, uint16_t key);
    void generateRoundKeys(uint16_t masterKey);
    static uint8_t gfMul(uint8_t a, uint8_t b);

public:
    MiniAES(uint16_t masterKey);
    uint16_t encrypt(uint16_t plaintext);
    uint16_t decrypt(uint16_t ciphertext);
    static std::string blockToString(uint16_t block);
    static std::string nibbleToString(uint8_t nibble);
    uint16_t getRoundKey(int round) const { return roundKeys[round]; }
};
#endif 
