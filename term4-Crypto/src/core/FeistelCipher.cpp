#include "FeistelCipher.hpp"
#include <exception>
#include <stdexcept>
namespace crypto {
    FeistelCipher::FeistelCipher(std::unique_ptr<FeistelNetwork> network)
        : m_feistelNetwork(std::move(network)) {
        if (!m_feistelNetwork) 
        {
            throw std::invalid_argument("sdfsf");
        }
    }
    
    void FeistelCipher::setKey(const ByteArray& key) {
        m_currentKey = key;
    }
    
    ByteArray FeistelCipher::encryptBlock(const ByteArray& block) {
        ByteArray working = block;
        preEncrypt(working);
        working = m_feistelNetwork->encrypt(working, m_currentKey);
        postEncrypt(working);
        return working;
    }
    
    ByteArray FeistelCipher::decryptBlock(const ByteArray& block) {
        ByteArray working = block;
        preDecrypt(working);
        working = m_feistelNetwork->decrypt(working, m_currentKey);
        postDecrypt(working);
        return working;
    }
}