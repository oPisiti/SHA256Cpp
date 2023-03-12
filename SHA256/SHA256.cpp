#include <bitset>
#include <cmath>
#include <cstring>
#include <cstddef>
#include <fstream> 
#include <iostream>
#include <vector>
#include <string>

int panic(std::string sMessage){
    std::cout << sMessage << std::endl;
    return 1;
}

inline uint32_t rightRotate(uint32_t num, int nTimes) {
    return (num >> nTimes) | (num << (sizeof(num) * 8 - nTimes));
}

// Based on https://qvault.io/cryptography/how-sha-2-works-step-by-step-sha-256/
void SHA256(std::ifstream& fInputFile) {
    // Getting the file's size
    const auto begin = fInputFile.tellg();
    fInputFile.seekg(0, std::ios::end);
    const auto end = fInputFile.tellg();
    const auto iFileSizeInBytes = (end-begin);
    fInputFile.seekg(0, std::ios::beg);

    // Initializing variables
    const auto iSizeFileInBits = iFileSizeInBytes * 8;
    size_t sizeHash = ceil((iSizeFileInBits + 64.0f) / 512) * 64;
    std::vector<std::byte> hash;                                   // Each char is an 8 bit word
    hash.reserve(sizeHash);   

    std::byte bZero{0x00};
    for (size_t i = 0; i < sizeHash; i++)  hash[i] = bZero;        // Setting all bits to 0

    // 1 - Pre-processing
    // https://codereview.stackexchange.com/questions/222021/read-file-into-vectorbyte
    for (std::size_t i = 0; i < iFileSizeInBytes; i++) fInputFile.read(reinterpret_cast<char*>(&hash[i]), 1);
    std::byte b0x80{0x80};
    hash[iFileSizeInBytes] = b0x80;
    
    // How many relevant bits in iSizeFileInBits
    unsigned iTMPSizeFileInBits, var = iSizeFileInBits;
    for (iTMPSizeFileInBits = 0; var != 0; ++iTMPSizeFileInBits) var >>= 1;

    // How many positions in hash array it will take to write iSizeFileInBits wholly
    unsigned int charPositions = iTMPSizeFileInBits / 8 + 1;

    // Writing the binary iSizeFileInBits into hash array. If iSizeFileInBits (binary) takes up more than 8 bits, the 9th onwards
    // must be written in hash[-1] position. Done with bitshifting 8*i each time
    for (int i = 0; i < charPositions; i++) hash[sizeHash - i - 1] = (std::byte)(iSizeFileInBits >> 8 * i) ;

    // 2 - Initialize Hash Values (h)
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    // 3 - Initialize Round Constants (k)
    const uint32_t k[64] = {    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

     // 4 - Chunk Loop
    for (size_t chunk = 0; chunk < sizeHash / 64; chunk++) {

        // 5 - Create Message Schedule (w)
        uint32_t w[64];
     
        uint32_t j = chunk * 64;
        for (size_t i = 0; i < 16; i++)   w[i] = ((uint32_t)hash[j + 4 * i] << 24) | ((uint32_t)hash[j + 4 * i + 1] << 16) | ((uint32_t)hash[j + 4 * i + 2] << 8) | (uint32_t)hash[j + 4 * i + 3];
        for (size_t i = 16; i < 64; i++)  w[i] = 0x00;              // Setting all other bits to 0

        uint32_t s0, s1;
        for (int i = 16; i < 64; i++) {
            s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
            s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        // 6 - Compression
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (int i = 0; i < 64; i++) {
            s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);

            uint32_t temp1 = h + s1 + ch + k[i] + w[i];
            s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;

            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }     
        
        // 7 - Modify Final Values
        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
        h5 = h5 + f;
        h6 = h6 + g;
        h7 = h7 + h;
    }

    printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", h0, h1, h2, h3, h4, h5, h6, h7);

}

int main(int argc, char* argv[]){
    const std::string sUsage = "Usage: SHA256 [file] [-t text]";
    if(argc < 2) panic(sUsage);

    bool bInputIsFile = true;
    std::ifstream fInputFile;

    for(int i = 1; i < argc; i++){
        // Setting flags
        if(strcmp(argv[i], "-") == 0){
            panic(sUsage);
        }
        if(strcmp(argv[i], "-t") == 0){
            bInputIsFile = false;
            continue;
        }

        // Getting the input into sMessage variable
        if(bInputIsFile){
            fInputFile.open(argv[i], std::ios::binary);
            if(!fInputFile.is_open()) panic("Unable to open file\n");
        }
        // else{
        //     sMessage = argv[i];
        // }

        // Calling hash function
        SHA256(fInputFile);

        // Clean up
        fInputFile.close();
    }
}