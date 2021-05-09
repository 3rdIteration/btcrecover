/*
    In- and out- buffer structures (of int32), with variable sizes, for hashing.
    These allow indexing just using just get_global_id(0)
    Variables tagged with <..> are replaced, so we can specify just enough room for the data.
    These are:
        - hashBlockSize_bits   : The hash's block size in Bits
        - inMaxNumBlocks      : per hash operation
        - hashDigestSize_bits   : The hash's digest size in Bits

    Originally adapted from Bjorn Kerler's sha256.cl
    MIT License
*/
#define DEBUG 1

// All macros left defined for usage in the program
#define ceilDiv(n,d) (((n) + (d) - 1) / (d))
// All important now, defining whether we're working with unsigned ints or longs
#define wordSize 4

// Practical sizes of buffers, in words.
#define inBufferSize ceilDiv(128, wordSize)


// Ultimately hoping to faze out the Size_int32/long64,
//   in favour of just size (_word implied)
#define word unsigned int

unsigned int SWAP (unsigned int val)
{
    return (rotate(((val) & 0x00FF00FF), 24U) | rotate(((val) & 0xFF00FF00), 8U));
}

// ====  Define the structs with the right word size  =====
//  Helpful & more cohesive to have the lengths of structures as words too,
//   (rather than unsigned int for both)
typedef struct {
    word length; // in bytes
    word buffer[inBufferSize];
} inbuf;

typedef struct {
    word buffer[16];
} outbuf;

// Salt buffer, used by pbkdf2 & pbe
typedef struct {
    word length; // in bytes
    word buffer[8];
} saltbuf;


// ========== Debugging function ============

#ifdef DEBUG
#if DEBUG

    #define def_printFromWord(tag, funcName, end)               \
    /* For printing the string of bytes stored in an array of words.
    Option to print hex. */    \
    static void funcName(tag const word *arr, const unsigned int len_bytes, const bool hex)\
    {                                           \
        for (int j = 0; j < len_bytes; j++){    \
            word v = arr[j / wordSize];                 \
            word r = (j % wordSize) * 8;                \
            /* Prints little endian, since that's what we use */   \
            v = (v >> r) & 0xFF;                \
            if (hex) {                          \
                printf("%02x", v);              \
            } else {                            \
                printf("%c", (char)v);          \
            }                                   \
        }                                       \
        printf(end);                            \
    }

    def_printFromWord(__private, printFromWord, "")
    def_printFromWord(__global, printFromWord_glbl, "")
    def_printFromWord(__private, printFromWord_n, "\n")
    def_printFromWord(__global, printFromWord_glbl_n, "\n")

#endif
#endif/*
    Original:
    SHA1 OpenCL Optimized kernel
    (c) B. Kerler 2018
    MIT License
*/

/*
    (small) Changes:
    outbuf and inbuf structs defined using the buffer_structs_template
    func_sha256 renamed to hash_main
*/

#define F1(x,y,z)   (bitselect(z,y,x))
#define F0(x,y,z)   (bitselect (x, y, ((x) ^ (z))))
#define mod(x,y) ((x)-((x)/(y)*(y)))
#define shr32(x,n) ((x) >> (n))
#define rotl32(a,n) rotate ((a), (n))

#define S0(x) (rotl32 ((x), 25u) ^ rotl32 ((x), 14u) ^ shr32 ((x),  3u))
#define S1(x) (rotl32 ((x), 15u) ^ rotl32 ((x), 13u) ^ shr32 ((x), 10u))
#define S2(x) (rotl32 ((x), 30u) ^ rotl32 ((x), 19u) ^ rotl32 ((x), 10u))
#define S3(x) (rotl32 ((x), 26u) ^ rotl32 ((x), 21u) ^ rotl32 ((x),  7u))

#define SHA256C00 0x428a2f98u
#define SHA256C01 0x71374491u
#define SHA256C02 0xb5c0fbcfu
#define SHA256C03 0xe9b5dba5u
#define SHA256C04 0x3956c25bu
#define SHA256C05 0x59f111f1u
#define SHA256C06 0x923f82a4u
#define SHA256C07 0xab1c5ed5u
#define SHA256C08 0xd807aa98u
#define SHA256C09 0x12835b01u
#define SHA256C0a 0x243185beu
#define SHA256C0b 0x550c7dc3u
#define SHA256C0c 0x72be5d74u
#define SHA256C0d 0x80deb1feu
#define SHA256C0e 0x9bdc06a7u
#define SHA256C0f 0xc19bf174u
#define SHA256C10 0xe49b69c1u
#define SHA256C11 0xefbe4786u
#define SHA256C12 0x0fc19dc6u
#define SHA256C13 0x240ca1ccu
#define SHA256C14 0x2de92c6fu
#define SHA256C15 0x4a7484aau
#define SHA256C16 0x5cb0a9dcu
#define SHA256C17 0x76f988dau
#define SHA256C18 0x983e5152u
#define SHA256C19 0xa831c66du
#define SHA256C1a 0xb00327c8u
#define SHA256C1b 0xbf597fc7u
#define SHA256C1c 0xc6e00bf3u
#define SHA256C1d 0xd5a79147u
#define SHA256C1e 0x06ca6351u
#define SHA256C1f 0x14292967u
#define SHA256C20 0x27b70a85u
#define SHA256C21 0x2e1b2138u
#define SHA256C22 0x4d2c6dfcu
#define SHA256C23 0x53380d13u
#define SHA256C24 0x650a7354u
#define SHA256C25 0x766a0abbu
#define SHA256C26 0x81c2c92eu
#define SHA256C27 0x92722c85u
#define SHA256C28 0xa2bfe8a1u
#define SHA256C29 0xa81a664bu
#define SHA256C2a 0xc24b8b70u
#define SHA256C2b 0xc76c51a3u
#define SHA256C2c 0xd192e819u
#define SHA256C2d 0xd6990624u
#define SHA256C2e 0xf40e3585u
#define SHA256C2f 0x106aa070u
#define SHA256C30 0x19a4c116u
#define SHA256C31 0x1e376c08u
#define SHA256C32 0x2748774cu
#define SHA256C33 0x34b0bcb5u
#define SHA256C34 0x391c0cb3u
#define SHA256C35 0x4ed8aa4au
#define SHA256C36 0x5b9cca4fu
#define SHA256C37 0x682e6ff3u
#define SHA256C38 0x748f82eeu
#define SHA256C39 0x78a5636fu
#define SHA256C3a 0x84c87814u
#define SHA256C3b 0x8cc70208u
#define SHA256C3c 0x90befffau
#define SHA256C3d 0xa4506cebu
#define SHA256C3e 0xbef9a3f7u
#define SHA256C3f 0xc67178f2u 

__constant uint k_sha256[64] =
{
  SHA256C00, SHA256C01, SHA256C02, SHA256C03,
  SHA256C04, SHA256C05, SHA256C06, SHA256C07,
  SHA256C08, SHA256C09, SHA256C0a, SHA256C0b,
  SHA256C0c, SHA256C0d, SHA256C0e, SHA256C0f,
  SHA256C10, SHA256C11, SHA256C12, SHA256C13,
  SHA256C14, SHA256C15, SHA256C16, SHA256C17,
  SHA256C18, SHA256C19, SHA256C1a, SHA256C1b,
  SHA256C1c, SHA256C1d, SHA256C1e, SHA256C1f,
  SHA256C20, SHA256C21, SHA256C22, SHA256C23,
  SHA256C24, SHA256C25, SHA256C26, SHA256C27,
  SHA256C28, SHA256C29, SHA256C2a, SHA256C2b,
  SHA256C2c, SHA256C2d, SHA256C2e, SHA256C2f,
  SHA256C30, SHA256C31, SHA256C32, SHA256C33,
  SHA256C34, SHA256C35, SHA256C36, SHA256C37,
  SHA256C38, SHA256C39, SHA256C3a, SHA256C3b,
  SHA256C3c, SHA256C3d, SHA256C3e, SHA256C3f,
};

#define SHA256_STEP(F0a,F1a,a,b,c,d,e,f,g,h,x,K)  \
{                                               \
  h += K;                                       \
  h += x;                                       \
  h += S3 (e);                           \
  h += F1a (e,f,g);                              \
  d += h;                                       \
  h += S2 (a);                           \
  h += F0a (a,b,c);                              \
}

#define SHA256_EXPAND(x,y,z,w) (S1 (x) + y + S0 (z) + w) 

static void sha256_process2 (const unsigned int *W, unsigned int *digest)
{
  unsigned int a = digest[0];
  unsigned int b = digest[1];
  unsigned int c = digest[2];
  unsigned int d = digest[3];
  unsigned int e = digest[4];
  unsigned int f = digest[5];
  unsigned int g = digest[6];
  unsigned int h = digest[7];

  unsigned int w0_t = W[0];
  unsigned int w1_t = W[1];
  unsigned int w2_t = W[2];
  unsigned int w3_t = W[3];
  unsigned int w4_t = W[4];
  unsigned int w5_t = W[5];
  unsigned int w6_t = W[6];
  unsigned int w7_t = W[7];
  unsigned int w8_t = W[8];
  unsigned int w9_t = W[9];
  unsigned int wa_t = W[10];
  unsigned int wb_t = W[11];
  unsigned int wc_t = W[12];
  unsigned int wd_t = W[13];
  unsigned int we_t = W[14];
  unsigned int wf_t = W[15];

  #define ROUND_EXPAND(i)                           \
  {                                                 \
    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP(i)                                                                   \
  {                                                                                       \
    SHA256_STEP (F0, F1, a, b, c, d, e, f, g, h, w0_t, k_sha256[i +  0]); \
    SHA256_STEP (F0, F1, h, a, b, c, d, e, f, g, w1_t, k_sha256[i +  1]); \
    SHA256_STEP (F0, F1, g, h, a, b, c, d, e, f, w2_t, k_sha256[i +  2]); \
    SHA256_STEP (F0, F1, f, g, h, a, b, c, d, e, w3_t, k_sha256[i +  3]); \
    SHA256_STEP (F0, F1, e, f, g, h, a, b, c, d, w4_t, k_sha256[i +  4]); \
    SHA256_STEP (F0, F1, d, e, f, g, h, a, b, c, w5_t, k_sha256[i +  5]); \
    SHA256_STEP (F0, F1, c, d, e, f, g, h, a, b, w6_t, k_sha256[i +  6]); \
    SHA256_STEP (F0, F1, b, c, d, e, f, g, h, a, w7_t, k_sha256[i +  7]); \
    SHA256_STEP (F0, F1, a, b, c, d, e, f, g, h, w8_t, k_sha256[i +  8]); \
    SHA256_STEP (F0, F1, h, a, b, c, d, e, f, g, w9_t, k_sha256[i +  9]); \
    SHA256_STEP (F0, F1, g, h, a, b, c, d, e, f, wa_t, k_sha256[i + 10]); \
    SHA256_STEP (F0, F1, f, g, h, a, b, c, d, e, wb_t, k_sha256[i + 11]); \
    SHA256_STEP (F0, F1, e, f, g, h, a, b, c, d, wc_t, k_sha256[i + 12]); \
    SHA256_STEP (F0, F1, d, e, f, g, h, a, b, c, wd_t, k_sha256[i + 13]); \
    SHA256_STEP (F0, F1, c, d, e, f, g, h, a, b, we_t, k_sha256[i + 14]); \
    SHA256_STEP (F0, F1, b, c, d, e, f, g, h, a, wf_t, k_sha256[i + 15]); \
  }

  ROUND_STEP (0);

  ROUND_EXPAND();
  ROUND_STEP(16);

  ROUND_EXPAND();
  ROUND_STEP(32);

  ROUND_EXPAND();
  ROUND_STEP(48);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

#define def_hash(funcName, passTag, hashTag)    \
/* The main hashing function */                 \
static void funcName(passTag const unsigned int *pass, int pass_len, hashTag unsigned int* hash)    \
{                                   \
    int plen=pass_len/4;            \
    if (mod(pass_len,4)) plen++;    \
                                    \
    hashTag unsigned int* p = hash; \
                                    \
    unsigned int W[0x10]={0};   \
    int loops=plen;             \
    int curloop=0;              \
    unsigned int State[8]={0};  \
    State[0] = 0x6a09e667;      \
    State[1] = 0xbb67ae85;      \
    State[2] = 0x3c6ef372;      \
    State[3] = 0xa54ff53a;      \
    State[4] = 0x510e527f;      \
    State[5] = 0x9b05688c;      \
    State[6] = 0x1f83d9ab;      \
    State[7] = 0x5be0cd19;      \
                        \
    while (loops>0)     \
    {                   \
        W[0x0]=0x0;     \
        W[0x1]=0x0;     \
        W[0x2]=0x0;     \
        W[0x3]=0x0;     \
        W[0x4]=0x0;     \
        W[0x5]=0x0;     \
        W[0x6]=0x0;     \
        W[0x7]=0x0;     \
        W[0x8]=0x0;     \
        W[0x9]=0x0;     \
        W[0xA]=0x0;     \
        W[0xB]=0x0;     \
        W[0xC]=0x0;     \
        W[0xD]=0x0;     \
        W[0xE]=0x0;     \
        W[0xF]=0x0;     \
                        \
        for (int m=0;loops!=0 && m<16;m++)      \
        {                                       \
            W[m]^=SWAP(pass[m+(curloop*16)]);   \
            loops--;                            \
        }                                       \
                                                \
        if (loops==0 && mod(pass_len,64)!=0)    \
        {                                       \
            unsigned int padding=0x80<<(((pass_len+4)-((pass_len+4)/4*4))*8);   \
            int v=mod(pass_len,64);         \
            W[v/4]|=SWAP(padding);          \
            if ((pass_len&0x3B)!=0x3B)      \
            {                               \
                /* Let's add length */      \
                W[0x0F]=pass_len*8;         \
            }                               \
        }                                   \
                                        \
        sha256_process2(W,State);       \
        curloop++;                      \
    }                                   \
                            \
    if (mod(plen,16)==0)    \
    {               \
        W[0x0]=0x0; \
        W[0x1]=0x0; \
        W[0x2]=0x0; \
        W[0x3]=0x0; \
        W[0x4]=0x0; \
        W[0x5]=0x0; \
        W[0x6]=0x0; \
        W[0x7]=0x0; \
        W[0x8]=0x0; \
        W[0x9]=0x0; \
        W[0xA]=0x0; \
        W[0xB]=0x0; \
        W[0xC]=0x0; \
        W[0xD]=0x0; \
        W[0xE]=0x0; \
        W[0xF]=0x0; \
        if ((pass_len&0x3B)!=0x3B)  \
        {                           \
            word padding=0x80<<(((pass_len+4)-((pass_len+4)/4*4))*8);   \
            W[0]|=SWAP(padding);    \
        }                           \
        /* Let's add length */      \
        W[0x0F]=pass_len*8;         \
                                    \
        sha256_process2(W,State);   \
    }   \
                            \
    p[0]=SWAP(State[0]);    \
    p[1]=SWAP(State[1]);    \
    p[2]=SWAP(State[2]);    \
    p[3]=SWAP(State[3]);    \
    p[4]=SWAP(State[4]);    \
    p[5]=SWAP(State[5]);    \
    p[6]=SWAP(State[6]);    \
    p[7]=SWAP(State[7]);    \
    return;                 \
}

def_hash(hash_global, __global, __global)
def_hash(hash_private, __private, __private)
def_hash(hash_glbl_to_priv, __global, __private)
def_hash(hash_priv_to_glbl, __private, __global)

#undef F0
#undef F1
#undef S0
#undef S1
#undef S2
#undef S3

#undef mod
#undef shr32
#undef rotl32

__kernel void hash_main(__global const inbuf * inbuffer, __global outbuf * outbuffer)
{
    unsigned int idx = get_global_id(0);
    // unsigned int hash[32/4]={0};
    hash_global(inbuffer[idx].buffer, inbuffer[idx].length, outbuffer[idx].buffer);
}
/*
    pbkdf2 and HMAC implementation
    requires implementation of PRF (pseudo-random function),
      probably using HMAC and an implementation of hash_main
*/
/*
    REQ: outBuf.buffer must have space for ceil(dkLen / PRF_output_bytes) * PRF_output_bytes
    REQ: PRF implementation MUST allow that output may be the salt (m in hmac)
    inBuffer / pwdBuffer / the like are not const to allow for padding
*/

// Determine (statically) the actual required buffer size
// Correct for both 64 & 32 bit
//   Just allowing for MD padding: 2 words for length, 1 for the 1-pad = 3 words
#define sizeForHash(reqSize) (ceilDiv((reqSize) + 2 + 1, 16) * 16)

__constant const unsigned int opad = 0x5c5c5c5c;
__constant const unsigned int ipad = 0x36363636;

__constant const word xoredPad = opad ^ ipad;

// Slightly ugly: large enough for hmac_main usage, and tight for pbkdf2
// #define m_buffer_size (8 + 1)

static void hmac(__global word *K, const word K_len_bytes,
    const word *m, const word m_len_bytes, word *output)
{
    // REQ: If K_len_bytes isn't divisible by 4/8, final word should be clean (0s to the end)
    // REQ: s digestSize is a multiple of 4/8 bytes

    /* Declare the space for input to the last hash function:
         Compute and write K_ ^ opad to the first block of this. This will be the only place that we store K_ */

    word input_2[16 + 8] = {0};
    word end;
    if (K_len_bytes <= 64)
    {
        end = ceilDiv(K_len_bytes, wordSize);
        // XOR with opad and slightly pad with zeros..
        input_2[0] = K[0] ^ opad;
        input_2[1] = K[1] ^ opad;
        input_2[2] = K[2] ^ opad;
        input_2[3] = K[3] ^ opad;
        input_2[4] = K[4] ^ opad;
        input_2[5] = K[5] ^ opad;
        input_2[6] = K[6] ^ opad;
        input_2[7] = K[7] ^ opad;
        input_2[8] = K[8] ^ opad;
        input_2[9] = K[9] ^ opad;
        input_2[0xA] = K[0xA] ^ opad;
        input_2[0xB] = K[0xB] ^ opad;
        input_2[0xC] = K[0xC] ^ opad;
        input_2[0xD] = K[0xD] ^ opad;
        input_2[0xE] = K[0xE] ^ opad;
        input_2[0xF] = K[0xF] ^ opad;
    } else {
        end = 8;
        // Hash K to get K'. XOR with opad..
        hash_glbl_to_priv(K, K_len_bytes, input_2);
        input_2[0] ^= opad;
        input_2[1] ^= opad;
        input_2[2] ^= opad;
        input_2[3] ^= opad;
        input_2[4] ^= opad;
        input_2[5] ^= opad;
        input_2[6] ^= opad;
        input_2[7] ^= opad;
        input_2[8] = opad;
        input_2[9] = opad;
        input_2[0xA] = opad;
        input_2[0xB] = opad;
        input_2[0xC] = opad;
        input_2[0xD] = opad;
        input_2[0xE] = opad;
        input_2[0xF] = opad;
    }
    // Copy K' ^ ipad into the first block.
    // Be careful: hash needs a whole block after the end. ceilDiv from buffer_structs
    // Slightly ugly: large enough for hmac_main usage, and tight for pbkdf2
    // #define m_buffer_size (8 + 1)
    // K' ^ ipad into the first block
    word input_1[16 + 9] = {0};

    input_1[0] = input_2[0]^xoredPad;
    input_1[1] = input_2[1]^xoredPad;
    input_1[2] = input_2[2]^xoredPad;
    input_1[3] = input_2[3]^xoredPad;
    input_1[4] = input_2[4]^xoredPad;
    input_1[5] = input_2[5]^xoredPad;
    input_1[6] = input_2[6]^xoredPad;
    input_1[7] = input_2[7]^xoredPad;
    input_1[8] = input_2[8]^xoredPad;
    input_1[9] = input_2[9]^xoredPad;
    input_1[0xA] = input_2[0xA]^xoredPad;
    input_1[0xB] = input_2[0xB]^xoredPad;
    input_1[0xC] = input_2[0xC]^xoredPad;
    input_1[0xD] = input_2[0xD]^xoredPad;
    input_1[0xE] = input_2[0xE]^xoredPad;
    input_1[0xF] = input_2[0xF]^xoredPad;


    // Slightly inefficient copying m in..
    word m_len_word = ceilDiv(m_len_bytes, wordSize);
    for (int j = 0; j < m_len_word; j++){
        input_1[16 + j] = m[j];
    }

    // Hash input1 into the second half of input2
    word leng = 64 + m_len_bytes;
    hash_private(input_1, leng, input_2 + 16);

    // Hash input2 into output!
    word temp_output[16 + 9] = {0};
    hash_private(input_2, 64 + 32, temp_output);
    for (int j = 0; j < (16 + 9); j++){
        output[j] = temp_output[j];
    }
}

#undef sizeForHash


// PRF
// Our PRF is the hmac using the hash. Commas remove need for bracketing
#define PRF(pwd, pwdLen_bytes, salt, saltLen_bytes, output) \
    hmac(pwd, pwdLen_bytes, salt, saltLen_bytes, output)


static void F(__global word *pwd, const word pwdLen_bytes,
    word *salt, const word saltLen_bytes,
    const unsigned int iters, unsigned int callI,
    __global word *output)
{
    // ASSUMPTION: salt array has wordSize bytes more room
    // Note salt is not const, so we can efficiently tweak the end of it

    // Add the integer to the end of the salt
    // NOTE! Always adding callI as just a u32
    //word overhang = saltLen_bytes % wordSize;
    word overhang=((saltLen_bytes)-((saltLen_bytes)/(wordSize)*(wordSize)));
    overhang *= 8; // convert to bits
    word saltLastI = saltLen_bytes / wordSize;

    // ! Crucial line: BE, moved as if it's a u32 but still within the word
    word be_callI = SWAP((word)callI) >> (8*(wordSize-4));
    if (overhang>0)
    {
        salt[saltLastI] |= be_callI << overhang;
        salt[saltLastI+1] = be_callI >> ((8*wordSize)-overhang);
    }
    else
    {
        salt[saltLastI]=be_callI;
    }

    // Make initial call, copy into output
    // This copy is avoidable, but only with __global / __private macro stuff
    word u[8] = {0};
    // +4 is correct even for 64 bit
    PRF(pwd, pwdLen_bytes, salt, saltLen_bytes + 4, u);
    output[0] = u[0];
    output[1] = u[1];
    output[2] = u[2];
    output[3] = u[3];
    output[4] = u[4];
    output[5] = u[5];
    output[6] = u[6];
    output[7] = u[7];

    // Perform all the iterations, reading salt from- AND writing to- u.
    for (unsigned int j = 1; j < iters; j++){
        PRF(pwd, pwdLen_bytes, u, 32, u);
        output[0]^=u[0];
        output[1]^=u[1];
        output[2]^=u[2];
        output[3]^=u[3];
        output[4]^=u[4];
        output[5]^=u[5];
        output[6]^=u[6];
        output[7]^=u[7];
    }
}

__kernel void pbkdf2(__global inbuf *inbuffer, __global const saltbuf *saltbuffer, __global outbuf *outbuffer,
    __private unsigned int iters, __private unsigned int dkLen_bytes)
{

    unsigned int idx = get_global_id(0);
    word pwdLen_bytes = inbuffer[idx].length;
    __global word *pwdBuffer = inbuffer[idx].buffer;
    __global word *currOutBuffer = outbuffer[idx].buffer;

    // Copy salt so that we can write our integer into the last 4 bytes
    word saltLen_bytes = saltbuffer[0].length;
    int saltLen = ceilDiv(saltLen_bytes, wordSize);
    word personal_salt[8+2] = {0};

    personal_salt[0] = saltbuffer[0].buffer[0];
    personal_salt[1] = saltbuffer[0].buffer[1];
    personal_salt[2] = saltbuffer[0].buffer[2];
    personal_salt[3] = saltbuffer[0].buffer[3];
    personal_salt[4] = saltbuffer[0].buffer[4];
    personal_salt[5] = saltbuffer[0].buffer[5];
    personal_salt[6] = saltbuffer[0].buffer[6];
    personal_salt[7] = saltbuffer[0].buffer[7];

    // Determine the number of calls to F that we need to make
    unsigned int nBlocks = ceilDiv(dkLen_bytes, 32);
    for (unsigned int j = 1; j <= nBlocks; j++)
    {
        F(pwdBuffer, pwdLen_bytes, personal_salt, saltbuffer[0].length, iters, j, currOutBuffer);
        currOutBuffer += 8;
    }
}


// Exposing HMAC in the same way. Useful for testing atleast.
__kernel void hmac_main(__global inbuf *inbuffer, __global const saltbuf *saltbuffer, __global outbuf *outbuffer)
{
    unsigned int idx = get_global_id(0);
    word pwdLen_bytes = inbuffer[idx].length;
    __global word *pwdBuffer = inbuffer[idx].buffer;

    // Copy salt just to cheer the compiler up
    int saltLen_bytes = (int)saltbuffer[0].length;
    int saltLen = ceilDiv(saltLen_bytes, wordSize);
    word personal_salt[8] = {0};

    personal_salt[0] = saltbuffer[0].buffer[0];
    personal_salt[1] = saltbuffer[0].buffer[1];
    personal_salt[2] = saltbuffer[0].buffer[2];
    personal_salt[3] = saltbuffer[0].buffer[3];
    personal_salt[4] = saltbuffer[0].buffer[4];
    personal_salt[5] = saltbuffer[0].buffer[5];
    personal_salt[6] = saltbuffer[0].buffer[6];
    personal_salt[7] = saltbuffer[0].buffer[7];

    // Call hmac, with local
    word out[8];
    
    hmac(pwdBuffer, pwdLen_bytes, personal_salt, saltLen_bytes, out);

    outbuffer[idx].buffer[0] = out[0];
    outbuffer[idx].buffer[1] = out[1];
    outbuffer[idx].buffer[2] = out[2];
    outbuffer[idx].buffer[3] = out[3];
    outbuffer[idx].buffer[4] = out[4];
    outbuffer[idx].buffer[5] = out[5];
    outbuffer[idx].buffer[6] = out[6];
    outbuffer[idx].buffer[7] = out[7];
}