#include "3DES.hpp"
#include <stdexcept>

namespace crypto {
    void TripleDESCipher::setKey(const Bytes& key) 
    {
        if (key.size() == 16) 
        {
            Bytes key1(key.begin(), key.begin() + 8);
            Bytes key2(key.begin() + 8, key.begin() + 16);

            m_des1.setKey(key1);
            m_des2.setKey(key2);
        } 
        else if (key.size() == 24) 
        {
            Bytes key1(key.begin(), key.begin() + 8);
            Bytes key2(key.begin() + 8, key.begin() + 16);
            Bytes key3(key.begin() + 16, key.begin() + 24);
            m_des1.setKey(key1);
            m_des2.setKey(key2);
            m_des3.setKey(key3);
        }
        else 
        {
            throw std::runtime_error("DES3Cipher: key must be 16 or 24 bytes");
        }
    }

    Bytes TripleDESCipher::encryptBlock(const Bytes& block)
    {
        Bytes encrypted;
        switch (m_mode) 
        {
            case EEE3:
                encrypted = m_des1.encryptBlock(block);
                encrypted = m_des2.encryptBlock(encrypted);
                encrypted = m_des3.encryptBlock(encrypted);
                break;

            case EDE3:
                encrypted = m_des1.encryptBlock(block);
                encrypted = m_des2.decryptBlock(encrypted);
                encrypted = m_des3.encryptBlock(encrypted);
                break;

            case EEE2:
                encrypted = m_des1.encryptBlock(block);
                encrypted = m_des2.encryptBlock(encrypted);
                encrypted = m_des1.encryptBlock(encrypted);
                break;

            case EDE2:
                encrypted = m_des1.encryptBlock(block);
                encrypted = m_des2.decryptBlock(encrypted);
                encrypted = m_des1.encryptBlock(encrypted);
                break;
        }

        return encrypted;
    }

    Bytes TripleDESCipher::decryptBlock(const Bytes& block)
    {
        Bytes decrypted;
        switch (m_mode) 
        {
            case EEE3:
                decrypted = m_des3.decryptBlock(block);
                decrypted = m_des2.decryptBlock(decrypted);
                decrypted = m_des1.decryptBlock(decrypted);
                break;

            case EDE3:
                decrypted = m_des3.decryptBlock(block);
                decrypted = m_des2.encryptBlock(decrypted);
                decrypted = m_des1.decryptBlock(decrypted);
                break;

            case EEE2:
                decrypted = m_des1.decryptBlock(block);
                decrypted = m_des2.decryptBlock(decrypted);
                decrypted = m_des1.decryptBlock(decrypted);
                break;

            case EDE2:
                decrypted = m_des1.decryptBlock(block);
                decrypted = m_des2.encryptBlock(decrypted);
                decrypted = m_des1.decryptBlock(decrypted);
                break;
        }

        return decrypted;
    }

    size_t TripleDESCipher::block_size() const
    {
        return 8;
    }
}