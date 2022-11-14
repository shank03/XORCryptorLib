/*
 * Copyright (c) 2022, Shashank Verma <shashank.verma2002@gmail.com>(shank03)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

/**
 * XORCryptor
 * <p>
 * Encrypts input text using XOR operation with individual characters
 * from input and key character.
 *
 * date: 21-Sep-2022
 */

#ifndef XOR_CRYPTOR_HPP
#define XOR_CRYPTOR_HPP

/// @brief A class to encrypt/decrypt files using XOR encryption
class XorCryptor {
    typedef unsigned char byte;
    typedef unsigned long long byte64;

public:
    enum Mode { ENCRYPT,
                DECRYPT,
                INVALID };

private:
    byte *p_cipher,
            *pe_table, *pd_table;
    byte64 l_cipher;

    static byte generate_mask(byte v);

    void generate_cipher_table();

public:
    XorCryptor(const byte *key, byte64 l_key);

    [[nodiscard]] byte *get_cipher() const { return p_cipher; }

    void encrypt_bytes(byte *src, byte64 src_len);

    void decrypt_bytes(byte *src, byte64 src_len);

    ~XorCryptor() {
        for (byte64 i = 0; i < l_cipher; i++) p_cipher[i] = 0;
        delete[] p_cipher;

        for (byte64 i = 0; i < 0x100; i++) pe_table[i] = 0;
        delete[] pe_table;
    }
};

#endif// XOR_CRYPTOR_HPP
