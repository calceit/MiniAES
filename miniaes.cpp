#include "miniaes.h"
#include <sstream>
#include <iomanip>

// S-box
const uint8_t MiniAES::SBOX[16] = {
    0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
};

// Inverse S-box 
const uint8_t MiniAES::INV_SBOX[16] = {
    0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF,
    0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5
};

// GF(2^4) multiplication table modulo x^4 + x + 1 
const uint8_t MiniAES::GF_MUL[16][16] = {
    {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
    {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF},
    {0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD},
    {0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2},
    {0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9},
    {0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3, 0x6},
    {0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4},
    {0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB},
    {0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1},
    {0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE},
    {0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1, 0xB, 0x6, 0xC},
    {0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3},
    {0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2, 0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8},
    {0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7},
    {0x0, 0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5},
    {0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC, 0x3, 0x8, 0x7, 0x5, 0xA}
};
const uint8_t MiniAES::RCON[3] = {0x0, 0x1, 0x2};
MiniAES::MiniAES(uint16_t masterKey) {
    generateRoundKeys(masterKey);
}
uint8_t MiniAES::getNibble(uint16_t block, int position) {
    
    int bitPosition = (3 - position) * 4;
    return (block >> bitPosition) & 0xF;
}
uint16_t MiniAES::setNibble(uint16_t block, int position, uint8_t value) {
    int bitPosition = (3 - position) * 4;
    uint16_t mask = ~(0xF << bitPosition);
    block &= mask;
    block |= (uint16_t)(value & 0xF) << bitPosition;
    return block;
}
uint8_t MiniAES::gfMul(uint8_t a, uint8_t b) {
    return GF_MUL[a & 0xF][b & 0xF];
}
uint16_t MiniAES::nibbleSub(uint16_t block) {
    uint16_t result = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t nibble = getNibble(block, i);
        uint8_t substituted = SBOX[nibble];
        result = setNibble(result, i, substituted);
    }
    return result;
}
uint16_t MiniAES::invNibbleSub(uint16_t block) {
    uint16_t result = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t nibble = getNibble(block, i);
        uint8_t substituted = INV_SBOX[nibble];
        result = setNibble(result, i, substituted);
    }
    return result;
}

uint16_t MiniAES::shiftRow(uint16_t block) {
    uint8_t p0 = getNibble(block, 0);
    uint8_t p1 = getNibble(block, 1);
    uint8_t p2 = getNibble(block, 2);
    uint8_t p3 = getNibble(block, 3);
    uint16_t result = 0;
    result = setNibble(result, 0, p0);
    result = setNibble(result, 1, p3);
    result = setNibble(result, 2, p2);
    result = setNibble(result, 3, p1);

    return result;
}
uint16_t MiniAES::mixColumn(uint16_t block) {
    uint8_t p0 = getNibble(block, 0);
    uint8_t p1 = getNibble(block, 1);
    uint8_t p2 = getNibble(block, 2);
    uint8_t p3 = getNibble(block, 3);
    uint8_t d0 = gfMul(0x3, p0) ^ gfMul(0x2, p1);
    uint8_t d1 = gfMul(0x2, p0) ^ gfMul(0x3, p1);
    uint8_t d2 = gfMul(0x3, p2) ^ gfMul(0x2, p3);
    uint8_t d3 = gfMul(0x2, p2) ^ gfMul(0x3, p3);

    uint16_t result = 0;
    result = setNibble(result, 0, d0);
    result = setNibble(result, 1, d1);
    result = setNibble(result, 2, d2);
    result = setNibble(result, 3, d3);

    return result;
}
uint16_t MiniAES::keyAddition(uint16_t block, uint16_t key) {
    return block ^ key;
}
void MiniAES::generateRoundKeys(uint16_t masterKey) {
    uint8_t w[12]; 
    w[0] = getNibble(masterKey, 0);
    w[1] = getNibble(masterKey, 1);
    w[2] = getNibble(masterKey, 2);
    w[3] = getNibble(masterKey, 3);
    roundKeys[0] = masterKey;
    w[4] = w[0] ^ SBOX[w[3]] ^ RCON[1];
    w[5] = w[1] ^ w[4];
    w[6] = w[2] ^ w[5];
    w[7] = w[3] ^ w[6];
    roundKeys[1] = 0;
    roundKeys[1] = setNibble(roundKeys[1], 0, w[4]);
    roundKeys[1] = setNibble(roundKeys[1], 1, w[5]);
    roundKeys[1] = setNibble(roundKeys[1], 2, w[6]);
    roundKeys[1] = setNibble(roundKeys[1], 3, w[7]);
    w[8] = w[4] ^ SBOX[w[7]] ^ RCON[2];
    w[9] = w[5] ^ w[8];
    w[10] = w[6] ^ w[9];
    w[11] = w[7] ^ w[10];
    roundKeys[2] = 0;
    roundKeys[2] = setNibble(roundKeys[2], 0, w[8]);
    roundKeys[2] = setNibble(roundKeys[2], 1, w[9]);
    roundKeys[2] = setNibble(roundKeys[2], 2, w[10]);
    roundKeys[2] = setNibble(roundKeys[2], 3, w[11]);
}

uint16_t MiniAES::encrypt(uint16_t plaintext) {
    uint16_t state = plaintext;
    state = keyAddition(state, roundKeys[0]);
    state = nibbleSub(state);
    state = shiftRow(state);
    state = mixColumn(state);
    state = keyAddition(state, roundKeys[1]);
    state = nibbleSub(state);
    state = shiftRow(state);
    state = keyAddition(state, roundKeys[2]);

    return state;
}
uint16_t MiniAES::decrypt(uint16_t ciphertext) {
    uint16_t state = ciphertext;
    state = keyAddition(state, roundKeys[2]);
    state = shiftRow(state); 
    state = invNibbleSub(state);
    state = keyAddition(state, roundKeys[1]);
    state = mixColumn(state); 
    state = shiftRow(state);
    state = invNibbleSub(state);
    state = keyAddition(state, roundKeys[0]);

    return state;
}
std::string MiniAES::blockToString(uint16_t block) {
    std::stringstream ss;
    for (int i = 3; i >= 0; i--) {
        ss << nibbleToString(getNibble(block, i));
        if (i > 0) ss << " ";
    }
    return ss.str();
}
std::string MiniAES::nibbleToString(uint8_t nibble) {
    std::stringstream ss;
    for (int i = 3; i >= 0; i--) {
        ss << ((nibble >> i) & 1);
    }
    return ss.str();
}
