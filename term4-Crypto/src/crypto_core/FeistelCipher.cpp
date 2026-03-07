#include "FeistelCipher.hpp"
#include <stdexcept>
namespace crypto 
{
    FeistelCipher::FeistelCipher(std::unique_ptr<FeistelNetwork> network)
        : m_feistelNetwork(std::move(network)) 
        {
            if (!m_feistelNetwork) 
            {
                throw std::invalid_argument("network pointer is nullptr");
            }
        }
    
    void FeistelCipher::setKey(const Bytes& key) 
    {
        m_currentKey = key;
        m_feistelNetwork->set_round_keys(m_currentKey);
    }
    
    Bytes FeistelCipher::encryptBlock(const Bytes& block) 
    {
        Bytes working = block;
        preEncrypt(working);
        working = m_feistelNetwork->encrypt(working);
        postEncrypt(working);
        return working;
    }
    
    Bytes FeistelCipher::decryptBlock(const Bytes& block) 
    {
        Bytes working = block;
        
        preEncrypt(working);
        working = m_feistelNetwork->decrypt(working);
        postEncrypt(working);
        return working;
    }
}