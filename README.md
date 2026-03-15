- MiniAES Implementation in C++, operates on 16-bit blocks & 16-bit keys. Each 4-bit nibble is treated as one state element & each internal state is 4 nibbles (p0 - p3).
- Core Round transformations implemented as follows:
  1. nibbleSub/invNibbleSub: 4-bit S-box/inverse S-box is applied to each nibble using lookup tables.
  2. shiftRow: p1 & p3 are swapped
  3. mixColumn: 2x2 MixColumns matrix is implemented over GF(24) using a GF_MUL table for multiplication.
  4. keyAddition: XORs the 16-bit state with the 16-bit round key.
- Key expansion is done by generateRoundKeys. 3 round keys (K0, K1, K2) are derived from the 16-bit master key. The schedule involves splitting the key into nibbles (w0 – w3), computing w4-w11 with S-box and recombining it into K1 & K2.  
