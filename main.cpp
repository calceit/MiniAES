#include <iostream>
#include <iomanip>
#include "miniaes.h"

using namespace std;

// converts binary string to uint16_t
// format: "p3 p2 p1 p0" where p0 is bits 0-3, p1 is bits 4-7, etc.
uint16_t binaryToBlock(const string& binary) {
    uint16_t result = 0;
    string cleaned;

    for (char c : binary) {
        if (c != ' ') cleaned += c;
    }
    if (cleaned.length() >= 16) {
        uint8_t p3 = 0, p2 = 0, p1 = 0, p0 = 0;

        for (int i = 0; i < 4; i++) {
            if (cleaned[i] == '1') p3 |= (1 << (3 - i));
        }
        for (int i = 0; i < 4; i++) {
            if (cleaned[4 + i] == '1') p2 |= (1 << (3 - i));
        }
        for (int i = 0; i < 4; i++) {
            if (cleaned[8 + i] == '1') p1 |= (1 << (3 - i));
        }
        for (int i = 0; i < 4; i++) {
            if (cleaned[12 + i] == '1') p0 |= (1 << (3 - i));
        }

        result = (p3 << 12) | (p2 << 8) | (p1 << 4) | p0;
    }

    return result;
}
void displayBlock(const string& label, uint16_t block) {
    cout << label << ": ";
    cout << "0x" << hex << setw(4) << setfill('0') << block << " = ";
    cout << MiniAES::blockToString(block) << dec << endl;
}

// Test Example 9 from the paper
void testExample9() {
    cout << "Testing Example 9 from the Mini-AES PDF\n";
    uint16_t plaintext = binaryToBlock("1001 1100 0110 0011");
    uint16_t key = binaryToBlock("1100 0011 1111 0000");
    uint16_t expectedCiphertext = binaryToBlock("0111 0010 1100 0110");

    cout << "Input Parameters:\n";
    displayBlock("Plaintext (P) ", plaintext);
    displayBlock("Key (K)       ", key);
    displayBlock("Expected (H)  ", expectedCiphertext);
    cout << "\n";
    MiniAES cipher(key);
    uint16_t ciphertext = cipher.encrypt(plaintext);
    cout << "Encryption Result:\n";
    displayBlock("Ciphertext    ", ciphertext);
    if (ciphertext == expectedCiphertext) {
        cout << "ENCRYPTION PASSED\n\n";
    } else {
        cout << "ENCRYPTION FAILED\n\n";
    }
    uint16_t decrypted = cipher.decrypt(ciphertext);
    cout << "Decryption Result:\n";
    displayBlock("Decrypted     ", decrypted);
    if (decrypted == plaintext) {
        cout << "DECRYPTION PASSED\n";
    } else {
        cout << "DECRYPTION FAILED\n";
    }

    cout << "\n";
}

// Additional test cases
void testAdditionalCases() {
    cout << "Checking More Test Cases:\n";
    struct TestCase {
        string name;
        uint16_t plaintext;
        uint16_t key;
    };

    TestCase tests[] = {
        {"All zeros", 0x0000, 0x0000},
        {"All ones", 0xFFFF, 0xFFFF},
        {"Simple pattern", 0x1234, 0x5678},
        {"Alternating", 0xAAAA, 0x5555}
    };

    for (const auto& test : tests) {
        cout << "Test: " << test.name << "\n";
        displayBlock("Plaintext ", test.plaintext);
        displayBlock("Key       ", test.key);

        MiniAES cipher(test.key);
        uint16_t encrypted = cipher.encrypt(test.plaintext);
        uint16_t decrypted = cipher.decrypt(encrypted);

        displayBlock("Encrypted ", encrypted);
        displayBlock("Decrypted ", decrypted);

        if (decrypted == test.plaintext) {
            cout << "PASSED\n";
        } else {
            cout << "FAILED\n";
        }
        cout << "\n";
    }
}
//Try user input
void interactiveMode() {
    cout << "Enter 16-bit plaintext (in hex, e.g., 9C63): ";
    uint16_t plaintext;
    cin >> hex >> plaintext;
    cout << "Enter 16-bit key (in hex, e.g., C3F0): ";
    uint16_t key;
    cin >> hex >> key;

    displayBlock("\nPlaintext ", plaintext);
    displayBlock("Key       ", key);

    MiniAES cipher(key);
    uint16_t encrypted = cipher.encrypt(plaintext);
    uint16_t decrypted = cipher.decrypt(encrypted);

    displayBlock("Encrypted ", encrypted);
    displayBlock("Decrypted ", decrypted);

    if (decrypted == plaintext) {
        cout << "\n✓ Verification: Decryption successful!\n";
    } else {
        cout << "\n✗ Verification: Decryption failed!\n";
    }
}

int main() {
    cout << "\n";
    cout << "     Mini-AES Implementation\n";
    cout << "\n";

    // Run Example 9 from the paper
    testExample9();

    // Run additional tests
    testAdditionalCases();

    // Interactive mode
    char choice;
    cout << "Would you like to try user input? (y/n): ";
    cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        interactiveMode();
    }

    cout << "\nProgram completed successfully.\n";
    return 0;
}
