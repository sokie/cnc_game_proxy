#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

#include <winsock2.h>
#include <boost/log/trivial.hpp>

class PeerchatCipher {
public:
    PeerchatCipher() : pc1(0), pc2(0), initialized(false) {
        // Initialize table with reversed range (255 down to 0)
        table.resize(256);
        for (int i = 0; i < 256; i++) {
            table[i] = static_cast<uint8_t>(255 - i);
        }
    }

    // Initialize cipher with challenge and game key
    void init(const std::string& challenge, const std::string& gamekey) {
        // Without a key there is nothing to derive the table from, and the
        // modulo below would divide by zero. game.gameKey is empty by default.
        if (gamekey.empty() || challenge.empty()) {
            BOOST_LOG_TRIVIAL(warning)
                << "[PEERCHAT] Cannot init cipher: game.gameKey is not set. "
                   "Decryption logging stays off.";
            initialized = false;
            return;
        }

        this->challenge = challenge;
        pc1 = 0;
        pc2 = 0;

        // Reset table to reversed range
        for (int i = 0; i < 256; i++) {
            table[i] = static_cast<uint8_t>(255 - i);
        }

        // XOR challenge with game key
        std::vector<uint8_t> chall(challenge.size());
        for (size_t i = 0; i < challenge.size(); i++) {
            chall[i] = static_cast<uint8_t>(challenge[i]) ^
                       static_cast<uint8_t>(gamekey[i % gamekey.size()]);
        }

        // Scramble table based on challenge (RC4-like key scheduling)
        uint8_t tmp = 0;
        for (size_t i = 0; i < table.size(); i++) {
            tmp = (tmp + chall[i % chall.size()] + table[i]) & 0xFF;

            // Swap table[i] and table[tmp]
            std::swap(table[i], table[tmp]);
        }

        initialized = true;
    }

    // Decrypt/encrypt data (XOR cipher - same operation for both)
    std::vector<uint8_t> crypt(const uint8_t* data, size_t len) {
        std::vector<uint8_t> output(len);

        for (size_t i = 0; i < len; i++) {
            pc1 = (pc1 + 1) & 0xFF;
            uint8_t tmp = table[pc1];
            pc2 = (pc2 + tmp) & 0xFF;

            // Swap table[pc1] and table[pc2]
            std::swap(table[pc1], table[pc2]);

            tmp = (tmp + table[pc1]) & 0xFF;
            output[i] = data[i] ^ table[tmp];
        }

        return output;
    }

    // Convenience overload for char buffer
    std::vector<uint8_t> crypt(const char* data, size_t len) {
        return crypt(reinterpret_cast<const uint8_t*>(data), len);
    }

    // Decrypt to string (for logging)
    std::string cryptToString(const char* data, size_t len) {
        auto decrypted = crypt(data, len);
        return std::string(decrypted.begin(), decrypted.end());
    }

    bool isInitialized() const { return initialized; }
    const std::string& getChallenge() const { return challenge; }

private:
    std::vector<uint8_t> table;
    uint8_t pc1;
    uint8_t pc2;
    std::string challenge;
    bool initialized;
};

// State for a peerchat connection
struct PeerchatState {
    SOCKET socket = INVALID_SOCKET;
    bool cryptRequested = false;       // Client sent CRYPT command
    bool encryptionEnabled = false;    // Received 705 response, encryption active
    PeerchatCipher sendCipher;         // Decrypt what client sends
    PeerchatCipher recvCipher;         // Decrypt what server sends
    std::string recvBuffer;            // Buffer for partial IRC messages

    void reset() {
        socket = INVALID_SOCKET;
        cryptRequested = false;
        encryptionEnabled = false;
        sendCipher = PeerchatCipher();
        recvCipher = PeerchatCipher();
        recvBuffer.clear();
    }
};
