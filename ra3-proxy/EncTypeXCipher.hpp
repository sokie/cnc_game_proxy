#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

#include <winsock2.h>
#include <boost/log/trivial.hpp>

class EncTypeXCipher {
public:
    EncTypeXCipher() : start(0), n1(0), n2(0), initialized(false) {
        encxkey.resize(261, 0);
    }

    // Initialize with game key and validate string from client request
    void init(const std::string& key, const std::string& validate) {
        // initDecoder() takes `i % key.size()`, so an empty key divides by zero.
        // game.gameKey is empty by default.
        if (key.empty()) {
            BOOST_LOG_TRIVIAL(warning)
                << "[MASTER] Cannot init cipher: game.gameKey is not set. "
                   "Decryption logging stays off.";
            initialized = false;
            return;
        }

        this->key.assign(key.begin(), key.end());
        this->validate.assign(validate.begin(), validate.end());
        start = 0;
        initialized = true;
    }

    // Decode server response - returns decrypted data, handles header on first call
    std::string decode(const uint8_t* data, size_t len) {
        if (!initialized || len == 0) {
            return std::string(reinterpret_cast<const char*>(data), len);
        }

        size_t offset = 0;

        if (start == 0) {
            // First packet - parse header
            if (len < 1) return "";

            size_t hdrLen = (data[0] ^ 0xEC) + 2;
            if (len < hdrLen) return "";

            size_t ivLen = data[hdrLen - 1] ^ 0xEA;
            start = hdrLen + ivLen;

            if (len < start) return "";

            // Extract IV and initialize decoder
            std::vector<uint8_t> iv(data + hdrLen, data + hdrLen + ivLen);
            initDecoder(iv);

            offset = start;
        }

        if (offset >= len) return "";

        // Decrypt the payload
        return decrypt(data + offset, len - offset);
    }

    // Convenience overload
    std::string decode(const char* data, size_t len) {
        return decode(reinterpret_cast<const uint8_t*>(data), len);
    }

    bool isInitialized() const { return initialized; }

private:
    void initDecoder(const std::vector<uint8_t>& salt) {
        this->salt = salt;

        // iv = copy of validate
        iv = validate;

        // Scramble iv with salt and key
        for (size_t i = 0; i < salt.size(); i++) {
            size_t keyIdx = i % key.size();
            size_t ivIdx = (key[keyIdx] * i) & 7;
            if (ivIdx < iv.size() && (i & 7) < iv.size()) {
                iv[ivIdx] ^= iv[i & 7] ^ salt[i];
            }
        }

        // Initialize encxkey with 0-255
        encxkey.resize(261);
        for (int i = 0; i < 256; i++) {
            encxkey[i] = static_cast<uint8_t>(i);
        }
        for (int i = 256; i < 261; i++) {
            encxkey[i] = 0;
        }

        n1 = 0;
        n2 = 0;

        if (iv.empty()) return;

        // Scramble table
        for (int i = 255; i >= 0; i--) {
            uint8_t t1 = func5(i);
            uint8_t t2 = encxkey[i];
            encxkey[i] = encxkey[t1];
            encxkey[t1] = t2;
        }

        // Set final state values
        encxkey[256] = encxkey[1];
        encxkey[257] = encxkey[3];
        encxkey[258] = encxkey[5];
        encxkey[259] = encxkey[7];
        encxkey[260] = encxkey[n1 & 0xff];
    }

    uint8_t func5(int cnt) {
        if (cnt == 0) return 0;

        int mask = 0;
        while (mask < cnt) {
            mask = (mask << 1) + 1;
        }

        int i = 0;
        int tmp;
        while (true) {
            n1 = encxkey[n1 & 0xff] + iv[n2];
            n2++;
            if (n2 >= static_cast<int>(iv.size())) {
                n2 = 0;
                n1 += static_cast<int>(iv.size());
            }
            tmp = n1 & mask;
            i++;
            if (i > 11) {
                tmp %= cnt;
            }
            if (tmp <= cnt) {
                break;
            }
        }
        return static_cast<uint8_t>(tmp);
    }

    std::string decrypt(const uint8_t* data, size_t len) {
        std::vector<uint8_t> output(len);

        for (size_t i = 0; i < len; i++) {
            uint8_t d = data[i];

            uint8_t a = encxkey[256];
            uint8_t b = encxkey[257];
            uint8_t c = encxkey[a];

            encxkey[256] = (a + 1) & 0xff;
            encxkey[257] = (b + c) & 0xff;

            a = encxkey[260];
            b = encxkey[257];
            b = encxkey[b];
            c = encxkey[a];
            encxkey[a] = b;

            a = encxkey[259];
            b = encxkey[257];
            a = encxkey[a];
            encxkey[b] = a;

            a = encxkey[256];
            b = encxkey[259];
            a = encxkey[a];
            encxkey[b] = a;

            a = encxkey[256];
            encxkey[a] = c;

            b = encxkey[258];
            a = encxkey[c];
            c = encxkey[259];
            b = (b + a) & 0xff;
            encxkey[258] = b;

            a = b;
            c = encxkey[c];
            b = encxkey[257];
            b = encxkey[b];
            a = encxkey[a];
            c = (c + b) & 0xff;

            b = encxkey[260];
            b = encxkey[b];
            c = (c + b) & 0xff;

            b = encxkey[c];
            c = encxkey[256];
            c = encxkey[c];
            a = (a + c) & 0xff;

            c = encxkey[b];
            b = encxkey[a];

            c ^= b ^ d;

            // Decrypt mode
            encxkey[259] = c;
            encxkey[260] = d;

            output[i] = c;
        }

        return std::string(output.begin(), output.end());
    }

    std::vector<uint8_t> key;
    std::vector<uint8_t> validate;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> encxkey;
    size_t start;
    int n1;
    int n2;
    bool initialized;
};

// State for a master server connection (port 28910)
struct MasterServerState {
    SOCKET socket = INVALID_SOCKET;
    std::string validate;              // Captured from client request
    bool cipherReady = false;          // Validate captured, ready to decrypt
    EncTypeXCipher decoder;            // Decoder for server responses

    void reset() {
        socket = INVALID_SOCKET;
        validate.clear();
        cipherReady = false;
        decoder = EncTypeXCipher();
    }
};
