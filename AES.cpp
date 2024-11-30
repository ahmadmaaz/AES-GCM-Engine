#include <iostream>
#include <cmath>
#include <ctime>
#include <random>
#include <vector>
using namespace std;

constexpr int SIZE = 4;
constexpr int KEYSIZE = 32;
constexpr int WORDCOUNT = 60;

class AES{
    
    private:
        vector<unsigned char> key; // 256 bits or 32 bytes 
        vector<vector<unsigned char>> ExpandedKey{WORDCOUNT, vector<unsigned char>(4)}; // 60 words or 240 bytes

        vector<unsigned char> Rcon = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};

        vector<vector<unsigned char>> mixMatrix = {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}
        };

        vector<vector<unsigned char>> SBOX ={

            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, //0
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, // 1
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, // 2
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, // 3
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, // 4
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, // 5
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, // 6
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, // 7
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, // 8
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, // 9
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, // a
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, // b
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, // c
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, // d
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, // e
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} // f
        };

        vector<vector<unsigned char>> ISBOX ={
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb}, // 0
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, // 1
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e}, // 2
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, // 3
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92}, // 4
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, // 5
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06}, // 6
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b}, // 7
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73}, // 8
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e}, // 9
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b}, // a
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4}, // b
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, // c
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef}, // d
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, // e
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} // f
        };


        vector<unsigned char> generateKey(){
            vector<unsigned char> generatedKey;
            random_device rd;
            mt19937 gen(rd());
            uniform_int_distribution<> dis(0, 255);

            for(int i = 0;i<KEYSIZE;++i){
                generatedKey.push_back(static_cast<unsigned char>(dis(gen)));
            }

            return generatedKey;
        }


        void expandKey(){
            for (int i = 0; i < 8; ++i) {
                vector<unsigned char> word; 
                for (int j = 0; j < 4; ++j) {    
                    word.push_back(key[i*4 + j]); 
                }
                ExpnadedKey[i] = word; 
            }

            
            for(int i = 8;i<WORDCOUNT;i++){
                vector<unsigned char> temp(4);

                if(i%8 == 0){

                    // left rotation of Ki-1
                    temp[0] = ExpnadedKey[i-1][1];
                    temp[1] = ExpnadedKey[i-1][2];
                    temp[2] = ExpnadedKey[i-1][3];
                    temp[3] = ExpnadedKey[i-1][0];

                    for(int j = 0;j<4;j++){
                        temp[j] = getSBOXvalue(temp[j]);
                    }   
                    // xor with Rcon of the round
                    temp[0] = temp[0]^Rcon[i/8];
                    temp = XorFunction(temp, ExpnadedKey[i-8]); 

                }
                else if(i%8 == 4){
                    temp = ExpnadedKey[i-1];
                    for(int j = 0;j<4;j++){
                        temp[j] = getSBOXvalue(temp[j]);
                    }
                    temp = XorFunction(temp, ExpnadedKey[i-8]);
                }
                else{
                    temp = XorFunction(ExpnadedKey[i-1],ExpnadedKey[i-8]);
                }

                ExpnadedKey[i] = temp;
            
            }
        }

        unsigned char getSBOXvalue(unsigned char val) {
            unsigned char row = val >> 4;
            unsigned char col = val & 0x0F;
            return SBOX[row][col];
        }

        vector<unsigned char> XorFunction(vector<unsigned char>& A, vector<unsigned char>& B){
            vector<unsigned char> C(4);
            C[0] = A[0]^B[0];
            C[1] = A[1]^B[1];
            C[2] = A[2]^B[2];
            C[3] = A[3]^B[3];
            return C;
        }

        vector<vector<unsigned char>> AddRoundKey(vector<vector<unsigned char>> initialState, int roundNumber){

            vector<vector<unsigned char>> newState(4, vector<unsigned char>(4));

            if(roundNumber>14 || roundNumber<0){
                throw invalid_argument("Invalid RoundNumber");
            }
            int start = roundNumber*4;
            int end = start+4;

            for(int i = start, idx = 0;i<end && idx<4;++i,++idx){
                for(int j = 0;j<4;++j){
                    newState[idx][j] = initialState[idx][j]^ExpandedKey[i][j];
                }
            }
            return newState;
        }

        void subBytes(vector<vector<unsigned char>>& state){
            for(int i = 0;i<4;++i){
                for(int j = 0;j<4;++j){
                    state[i][j] = getSBOXvalue(state[i][j]);
                }
            }
        }

        // here I shift upwards beacuse I have taken the words and state as a row
        // we have upwardCircularShift by 0, 1, 2 , 3 for columns 1, 2, 3, 4 respectively
        void ShiftRows(vector<vector<unsigned char>>& state){

            for (int col = 0; col < SIZE; ++col) {
                
                std::array<unsigned char, SIZE> tempColumn;

                // Store the current column in tempColumn
                for (int row = 0; row < SIZE; ++row) {
                    tempColumn[row] = state[row][col];
                }

                
                for (int row = 0; row < SIZE; ++row) {
                    int newRow = (row + SIZE - col) % SIZE;  // We shift upward by 'col' positions
                    state[newRow][col] = tempColumn[row];
                }
            }
        }

        unsigned char gmul(unsigned char a, unsigned char b) {
            unsigned char p = 0; // The product
            while (b) {
                if (b & 1) p ^= a; // If the least significant bit of b is set, add a to p
                bool high_bit_set = a & 0x80; // Check if the high bit of a is set
                a <<= 1; // Multiply a by 2
                if (high_bit_set) a ^= 0x1B; // XOR with the AES irreducible polynomial if needed
                b >>= 1; // Divide b by 2
            }
            return p;
        }

        // here the word is given by a row also 
        void mixCoulumns(vector<vector<unsigned char>>& state){
            for (int col = 0; col < 4; ++col) {
                vector<unsigned char> tempColumn(4);
                for (int row = 0; row < 4; ++row) {
                    tempColumn[row] =
                        gmul(state[0][col], mixMatrix[row][0]) ^
                        gmul(state[1][col], mixMatrix[row][1]) ^
                        gmul(state[2][col], mixMatrix[row][2]) ^
                        gmul(state[3][col], mixMatrix[row][3]);
                }
                for (int row = 0; row < 4; ++row) {
                    state[row][col] = tempColumn[row];
                }
            }
        }



    

    public:
        
        AES(): key(generateKey()){}

        void displayKey() const {

            cout << "AES key: ";
            for(unsigned char byte: key){
                cout << hex << (int)byte << " ";
            }
            cout << "\n";

        }
        void displayExpandedKey() const {
            cout << "Expanded Key:\n";
            for (int i = 0; i < ExpandedKey.size(); ++i) {
                cout << "Word " << i << ": ";
                for (unsigned char byte : ExpandedKey[i]) {
                    cout << hex << (int)byte << " ";
                }
                cout << "\n";
            }
        }
        void testExpandKey() {
            expandKey();
            displayExpandedKey();
        }
        

};

int main(){
    AES aes;
    aes.displayKey();
    aes.testExpandKey();
    return 0;
}