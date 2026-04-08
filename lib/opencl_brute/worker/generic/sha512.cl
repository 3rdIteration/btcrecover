/*
    Original copyright (sha256):
    OpenCL Optimized kernel
    (c) B. Kerler 2018
    MIT License

    Adapted for SHA512 by C.B .. apparently quite a while ago
    The moral of the story is always use UL on unsigned longs!
*/



// bitselect is "if c then b else a" for each bit
// so equivalent to (c & b) | ((~c) & a)
// Apple Silicon GPUs have a known bug where bitselect() produces
// incorrect results for 64-bit types.  Use portable equivalents.
#ifdef APPLE_GPU
#define choose(x,y,z)   ((x & y) ^ (~x & z))
#define bit_maj(x,y,z)  ((x & y) | (z & (x | y)))
#else
#define choose(x,y,z)   (bitselect(z,y,x))
// Cleverly determines majority vote, conditioning on x=z
#define bit_maj(x,y,z)   (bitselect (x, y, ((x) ^ (z))))
#endif

// On Apple Silicon, rotate() for 64-bit types is broken;
// rotr64/rotl64 are already handled in buffer_structs_template.cl




// ==============================================================================
// =========  S0,S1,s0,s1  ======================================================


#define S0(x) (rotr64(x,28ul) ^ rotr64(x,34ul) ^ rotr64(x,39ul))
#define S1(x) (rotr64(x,14ul) ^ rotr64(x,18ul) ^ rotr64(x,41ul))

#define little_s0(x) (rotr64(x,1ul) ^ rotr64(x,8ul) ^ ((x) >> 7ul))
#define little_s1(x) (rotr64(x,19ul) ^ rotr64(x,61ul) ^ ((x) >> 6ul))


// ==============================================================================
// =========  MD-pads the input, taken from md5.cl  =============================
// Adapted for unsigned longs
// Note that the padding is still in a distinct unsigned long to the appended length.


// 'highBit' macro is (i+1) bytes, all 0 but the last which is 0x80
//  where we are thinking Little-endian thoughts.
// Don't forget to call constants longs!!
#define highBit(i) (0x1UL << (8*i + 7))
#define fBytes(i) (0xFFFFFFFFFFFFFFFFUL >> (8 * (8-i)))
__constant unsigned long padLong[8] = {
    highBit(0), highBit(1), highBit(2), highBit(3),
    highBit(4), highBit(5), highBit(6), highBit(7)
};
__constant unsigned long maskLong[8] = {
    0, fBytes(1), fBytes(2), fBytes(3),     // strange behaviour for fBytes(0)
    fBytes(4), fBytes(5), fBytes(6), fBytes(7)
};

#define bs_long hashBlockSize_long64
#define def_md_pad_128(funcName, tag)               \
/* The standard padding, INPLACE,
    add a 1 bit, then little-endian original length mod 2^128 (not 64) at the end of a block
    RETURN number of blocks */                  \
static int funcName(tag unsigned long *msg, const long msgLen_bytes)      \
{                                                                       \
    /* Appends the 1 bit to the end, and 0s to the end of the byte */   \
    const unsigned int padLongIndex = ((unsigned int)msgLen_bytes) / 8;                \
    const unsigned int overhang = (((unsigned int)msgLen_bytes) - padLongIndex*8);     \
    /* Don't assume that there are zeros here! */                       \
    msg[padLongIndex] &= maskLong[overhang];                              \
    msg[padLongIndex] |= padLong[overhang];                               \
                                                                        \
    /* Previous code was horrible
        Now we zero until we reach a multiple of the block size,
        Skipping TWO longs to ensure there is room for the length */     \
    msg[padLongIndex + 1] = 0;                                          \
    msg[padLongIndex + 2] = 0;                                          \
    unsigned int i = 0;                                                 \
    for (i = padLongIndex + 3; i % bs_long != 0; i++)                   \
    {                                                                   \
        msg[i] = 0;                                                     \
    }                                                                   \
                                                                        \
    /* Determine the total number of blocks */                          \
    int nBlocks = i / bs_long;                                          \
    /* Add the bit length to the end, 128-bit, big endian? (source wikipedia)
       Seemingly this does require SWAPing, so perhaps it's little-endian? */           \
    msg[i-2] = 0;   /* For clarity */                                   \
    msg[i-1] = SWAP(msgLen_bytes*8);                                    \
                                                                        \
    return nBlocks;                                                     \
};                                                                      

// Define it with the various tags to cheer OpenCL up
def_md_pad_128(md_pad__global, __global)
def_md_pad_128(md_pad__private, __private)

#undef bs_long
#undef def_md_pad_128
#undef highBit
#undef fBytes




// ==============================================================================

__constant unsigned long k_sha256[80] =
{
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL, 0x3956c25bf348b538UL, 
    0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL, 0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 
    0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL, 0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 
    0xc19bf174cf692694UL, 0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL, 
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL, 0x983e5152ee66dfabUL, 
    0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL, 0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 
    0x06ca6351e003826fUL, 0x142929670a0e6e70UL, 0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 
    0x53380d139d95b3dfUL, 0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL, 
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL, 0xd192e819d6ef5218UL, 
    0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL, 0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 
    0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL, 0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 
    0x682e6ff3d6b2b8a3UL, 0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL, 
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL, 0xca273eceea26619cUL, 
    0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL, 0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 
    0x113f9804bef90daeUL, 0x1b710b35131c471bUL, 0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 
    0x431d67c49c100d4cUL, 0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL   
};


#define SHA512_STEP(a,b,c,d,e,f,g,h,x,K)  \
/**/                \
{                   \
  h += K + S1(e) + choose(e,f,g) + x; /* h = temp1 */   \
  d += h;           \
  h += S0(a) + bit_maj(a,b,c);  \
}


static void printAll(unsigned long a, unsigned long b, unsigned long c, unsigned long d,
                unsigned long e, unsigned long f, unsigned long g, unsigned long h)
{
    printf("a = %lX\n", a);
    printf("b = %lX\n", b);
    printf("c = %lX\n", c);
    printf("d = %lX\n", d);
    printf("e = %lX\n", e);
    printf("f = %lX\n", f);
    printf("g = %lX\n", g);
    printf("h = %lX\n\n", h);
}

#define ROUND_STEP(i) \
/**/                  \
{                     \
    SHA512_STEP(a, b, c, d, e, f, g, h, W[i + 0], k_sha256[i +  0]); \
    SHA512_STEP(h, a, b, c, d, e, f, g, W[i + 1], k_sha256[i +  1]); \
    SHA512_STEP(g, h, a, b, c, d, e, f, W[i + 2], k_sha256[i +  2]); \
    SHA512_STEP(f, g, h, a, b, c, d, e, W[i + 3], k_sha256[i +  3]); \
    SHA512_STEP(e, f, g, h, a, b, c, d, W[i + 4], k_sha256[i +  4]); \
    SHA512_STEP(d, e, f, g, h, a, b, c, W[i + 5], k_sha256[i +  5]); \
    SHA512_STEP(c, d, e, f, g, h, a, b, W[i + 6], k_sha256[i +  6]); \
    SHA512_STEP(b, c, d, e, f, g, h, a, W[i + 7], k_sha256[i +  7]); \
    SHA512_STEP(a, b, c, d, e, f, g, h, W[i + 8], k_sha256[i +  8]); \
    SHA512_STEP(h, a, b, c, d, e, f, g, W[i + 9], k_sha256[i +  9]); \
    SHA512_STEP(g, h, a, b, c, d, e, f, W[i + 10], k_sha256[i + 10]); \
    SHA512_STEP(f, g, h, a, b, c, d, e, W[i + 11], k_sha256[i + 11]); \
    SHA512_STEP(e, f, g, h, a, b, c, d, W[i + 12], k_sha256[i + 12]); \
    SHA512_STEP(d, e, f, g, h, a, b, c, W[i + 13], k_sha256[i + 13]); \
    SHA512_STEP(c, d, e, f, g, h, a, b, W[i + 14], k_sha256[i + 14]); \
    SHA512_STEP(b, c, d, e, f, g, h, a, W[i + 15], k_sha256[i + 15]); \
}


#define def_hash(funcName, inputTag, hashTag, mdPadFunc, printFromLongFunc)   \
/* The main hashing function */     \
static void funcName(inputTag unsigned long *input, const unsigned int length, hashTag unsigned long* hash)    \
{                                   \
    /* Do the padding - we weren't previously for some reason */            \
    const unsigned int nBlocks = mdPadFunc(input, (const unsigned long) length);      \
    /*if (length == 8){   \
        printf("Padded input: ");   \
        printFromLongFunc(input, hashBlockSize_bytes, true); \
    }*/   \
                                    \
    unsigned long W[0x50]={0};      \
    /* state which is repeatedly processed & added to */    \
    unsigned long State[8]={0};    \
    State[0] = 0x6a09e667f3bcc908UL;	\
    State[1] = 0xbb67ae8584caa73bUL;	\
    State[2] = 0x3c6ef372fe94f82bUL;	\
    State[3] = 0xa54ff53a5f1d36f1UL;	\
    State[4] = 0x510e527fade682d1UL;	\
    State[5] = 0x9b05688c2b3e6c1fUL;	\
    State[6] = 0x1f83d9abfb41bd6bUL;	\
    State[7] = 0x5be0cd19137e2179UL;	\
                                    \
    unsigned long a,b,c,d,e,f,g,h;  \
                                \
    /* loop for each block */   \
    for (int block_i = 0; block_i < nBlocks; block_i++)     \
    {                                           \
        /* No need to (re-)initialise W.
            Note that the input pointer is updated */    \
        W[0] = SWAP(input[0]);	\
        W[1] = SWAP(input[1]);	\
        W[2] = SWAP(input[2]);	\
        W[3] = SWAP(input[3]);	\
        W[4] = SWAP(input[4]);	\
        W[5] = SWAP(input[5]);	\
        W[6] = SWAP(input[6]);	\
        W[7] = SWAP(input[7]);	\
        W[8] = SWAP(input[8]);	\
        W[9] = SWAP(input[9]);	\
        W[10] = SWAP(input[10]);	\
        W[11] = SWAP(input[11]);	\
        W[12] = SWAP(input[12]);	\
        W[13] = SWAP(input[13]);	\
        W[14] = SWAP(input[14]);	\
        W[15] = SWAP(input[15]);	\
                            \
        for (int i = 16; i < 80; i++)   \
        {                   \
            W[i] = W[i-16] + little_s0(W[i-15]) + W[i-7] + little_s1(W[i-2]);   \
        }               \
                        \
        a = State[0];   \
        b = State[1];   \
        c = State[2];   \
        d = State[3];   \
        e = State[4];   \
        f = State[5];   \
        g = State[6];   \
        h = State[7];   \
                        \
        /* Note loop is only 5 */  \
        for (int i = 0; i < 80; i += 16)    \
        {                   \
            ROUND_STEP(i)   \
        }                   \
                        \
        State[0] += a;  \
        State[1] += b;  \
        State[2] += c;  \
        State[3] += d;  \
        State[4] += e;  \
        State[5] += f;  \
        State[6] += g;  \
        State[7] += h;  \
                        \
        input += hashBlockSize_long64;   \
    }                   \
                        \
    hash[0]=SWAP(State[0]);   \
    hash[1]=SWAP(State[1]);   \
    hash[2]=SWAP(State[2]);   \
    hash[3]=SWAP(State[3]);   \
    hash[4]=SWAP(State[4]);   \
    hash[5]=SWAP(State[5]);   \
    hash[6]=SWAP(State[6]);   \
    hash[7]=SWAP(State[7]);   \
    return;             \
}

def_hash(hash_global, __global, __global, md_pad__global, printFromLong_glbl_n)
def_hash(hash_private, __private, __private, md_pad__private, printFromLong_n)
def_hash(hash_glbl_to_priv, __global, __private, md_pad__global, printFromLong_glbl_n)
def_hash(hash_priv_to_glbl, __private, __global, md_pad__private, printFromLong_n)

#undef bit_maj
#undef choose
#undef S0
#undef S1
#undef little_s0
#undef little_s1

__kernel void hash_main(__global inbuf * inbuffer, __global outbuf * outbuffer)
{
    unsigned int idx = get_global_id(0);
    hash_global(inbuffer[idx].buffer, inbuffer[idx].length, outbuffer[idx].buffer);
}
