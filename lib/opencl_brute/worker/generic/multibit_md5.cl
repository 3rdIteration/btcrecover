/*
    MultiBit MD5 OpenCL kernel with AES-CBC decryption

    This kernel performs the 3 MD5 iterations required for MultiBit wallet key derivation,
    followed by AES-CBC decryption of the first 16-byte encrypted block using the derived keys.

    Expects:
    - Input buffer: passwords in `inbuf` format
    - Salt buffer: single salt in `saltbuf` format
    - Output buffer: 68 bytes per password (1B match + 15B padding + 16B decrypted block + 32B AES key + 16B IV)
    - Encrypted block: 16 bytes, passed as __global uchar*
*/

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

__kernel void multibit_md5_main(__global inbuf* inbuffer,
                                __global saltbuf* saltbuffer,
                                __global outbuf* outbuffer,
                                __global const uchar* encrypted_block) {

    const uint idx = get_global_id(0);

    // Get password data
    __global word* password_words = inbuffer[idx].buffer;
    const word password_len = inbuffer[idx].length;

    // Get salt data
    __global word* salt_words = saltbuffer->buffer;
    const word salt_len = saltbuffer->length;

    // Convert password and salt to byte arrays
    uchar password_bytes[256];
    uchar salt_bytes[32];

    for (int i = 0; i < password_len; i++) {
        int w_idx = i / wordSize;
        int b_idx = i % wordSize;
        password_bytes[i] = (password_words[w_idx] >> (b_idx * 8)) & 0xFF;
    }

    for (int i = 0; i < salt_len; i++) {
        int w_idx = i / wordSize;
        int b_idx = i % wordSize;
        salt_bytes[i] = (salt_words[w_idx] >> (b_idx * 8)) & 0xFF;
    }

    // Concatenate password + salt
    uchar salted[272];  // max password 256 + max salt 16
    for (int i = 0; i < password_len; i++) {
        salted[i] = password_bytes[i];
    }
    for (int i = 0; i < salt_len; i++) {
        salted[password_len + i] = salt_bytes[i];
    }

    // First MD5: hash(password + salt) -> key1
    uint key1[4];
    hash_private((__private uint*)salted, password_len + salt_len, key1);

    // Second MD5: hash(key1 + password + salt) -> key2
    uchar key1_salted[288];
    for (int i = 0; i < 16; i++) {
        key1_salted[i] = ((__private uchar*)key1)[i];
    }
    for (int i = 0; i < password_len + salt_len; i++) {
        key1_salted[16 + i] = salted[i];
    }

    uint key2[4];
    hash_private((__private uint*)key1_salted, 16 + password_len + salt_len, key2);

    // Third MD5: hash(key2 + password + salt) -> iv
    uchar key2_salted[288];
    for (int i = 0; i < 16; i++) {
        key2_salted[i] = ((__private uchar*)key2)[i];
    }
    for (int i = 0; i < password_len + salt_len; i++) {
        key2_salted[16 + i] = salted[i];
    }

    uint iv[4];
    hash_private((__private uint*)key2_salted, 16 + password_len + salt_len, iv);

    // Prepare key and IV as byte arrays
    uchar aes_key[32];
    uchar aes_iv[16];
    for (int i = 0; i < 16; i++) {
        aes_key[i] = ((__private uchar*)key1)[i];
        aes_key[16 + i] = ((__private uchar*)key2)[i];
        aes_iv[i] = ((__private uchar*)iv)[i];
    }

    // Copy encrypted block from global buffer
    uchar local_block[16];
    for (int i = 0; i < 16; i++) {
        local_block[i] = encrypted_block[i];
    }

    // Decrypt using AES-CBC
    __global uchar* dbg = (__global uchar*)(&outbuffer[idx]);


    uchar decrypted[16];
    aes_cbc_decrypt_block(aes_key, aes_iv, local_block, decrypted);

    // Check for recognizable prefix byte in decrypted data
    uchar match = 0;
    uchar b0 = decrypted[0];
    if (b0 == 'L' || b0 == 'K' || b0 == '5' || b0 == 'Q' || b0 == 0x0A || b0 == '#'){
        match = 1;
    }

    // Write output: match flag + decrypted + key1 + key2 + iv
    __global word* output = outbuffer[idx].buffer;

    // match flag (1 word)
    output[0] = (word)match;

    // decrypted block (16 bytes -> 4 words)
    for (int i = 0; i < 16; i += wordSize) {
        word packed = 0;
        for (int j = 0; j < wordSize; j++) {
            packed |= ((word)decrypted[i + j]) << (8 * j);
        }
        output[1 + i / wordSize] = packed;
    }

    // key1 (16 bytes -> 4 words)
    for (int i = 0; i < 16; i += wordSize) {
        word packed = 0;
        for (int j = 0; j < wordSize; j++) {
            packed |= ((word)((__private uchar*)key1)[i + j]) << (8 * j);
        }
        output[5 + i / wordSize] = packed;
    }

    // key2 (16 bytes -> 4 words)
    for (int i = 0; i < 16; i += wordSize) {
        word packed = 0;
        for (int j = 0; j < wordSize; j++) {
            packed |= ((word)((__private uchar*)key2)[i + j]) << (8 * j);
        }
        output[9 + i / wordSize] = packed;
    }

    // iv (16 bytes -> 4 words)
    for (int i = 0; i < 16; i += wordSize) {
        word packed = 0;
        for (int j = 0; j < wordSize; j++) {
            packed |= ((word)((__private uchar*)iv)[i + j]) << (8 * j);
        }
        output[13 + i / wordSize] = packed;
    }
} 
