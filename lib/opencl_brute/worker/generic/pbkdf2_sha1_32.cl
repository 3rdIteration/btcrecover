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
#define DEBUG 0    // Set to 1 to enable debug utilities for troubleshooting

// All macros left defined for usage in the program
#define ceilDiv(n,d) (((n) + (d) - 1) / (d))

// All important now, defining whether we're working with unsigned ints or longs
#define wordSize 4

// Practical sizes of buffers, in words.
#define inBufferSize ceilDiv(128, wordSize)
#define outBufferSize ceilDiv(40, wordSize)
#define saltBufferSize ceilDiv(8, wordSize)
#define ctBufferSize ceilDiv(0, wordSize)

//
#define hashBlockSize_bytes ceilDiv(512, 8) /* Needs to be a multiple of 4, or 8 when we work with unsigned longs */
#define hashDigestSize_bytes ceilDiv(160, 8)

// just Size always implies _word
#define hashBlockSize ceilDiv(hashBlockSize_bytes, wordSize)
#define hashDigestSize ceilDiv(hashDigestSize_bytes, wordSize)


// Ultimately hoping to faze out the Size_int32/long64,
//   in favour of just size (_word implied)
#if wordSize == 4
    #define hashBlockSize_int32 hashBlockSize
    #define hashDigestSize_int32 hashDigestSize
    #define word unsigned int

    unsigned int SWAP (unsigned int val)
    {
        return (rotate(((val) & 0x00FF00FF), 24U) | rotate(((val) & 0xFF00FF00), 8U));
    }

#elif wordSize == 8
    // Initially for use in SHA-512
    #define hashBlockSize_long64 hashBlockSize
    #define hashDigestSize_long64 hashDigestSize
    #define word unsigned long
    #define rotl64(a,n) (rotate ((a), (n)))
    #define rotr64(a,n) (rotate ((a), (64ul-n)))

    unsigned long SWAP (const unsigned long val)
    {
        // ab cd ef gh -> gh ef cd ab using the 32 bit trick
        unsigned long tmp = (rotr64(val & 0x0000FFFF0000FFFFUL, 16UL) | rotl64(val & 0xFFFF0000FFFF0000UL, 16UL));

        // Then see this as g- e- c- a- and -h -f -d -b to swap within the pairs,
        // gh ef cd ab -> hg fe dc ba
        return (rotr64(tmp & 0xFF00FF00FF00FF00UL, 8UL) | rotl64(tmp & 0x00FF00FF00FF00FFUL, 8UL));
    }
#endif



// ====  Define the structs with the right word size  =====
//  Helpful & more cohesive to have the lengths of structures as words too,
//   (rather than unsigned int for both)
typedef struct {
    word length; // in bytes
    word buffer[inBufferSize];
} inbuf;

typedef struct {
    word buffer[outBufferSize];
} outbuf;

// Salt buffer, used by pbkdf2 & pbe
typedef struct {
    word length; // in bytes
    word buffer[saltBufferSize];
} saltbuf;

// ciphertext buffer, used in pbe.
// no code relating to this in the opencl.py core, dealt with in signal_pbe_mac.cl as it's a special case
typedef struct {
    word length; // in bytes
    word buffer[ctBufferSize];
} ctbuf;




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
            word r = mod(j,wordSize) * 8;                \
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
    PBKDF2 SHA1 OpenCL Optimized kernel, limited to max. 32 chars for salt and password
    (c) B. Kerler 2017
    MIT License
*/

#define rotl32(a,n) rotate ((a), (n))

#define mod(x,y) x-(x/y*y)

#define F2(x,y,z)  ((x) ^ (y) ^ (z))
#define F1(x,y,z)   (bitselect(z,y,x))
#define F0(x,y,z)   (bitselect (x, y, (x ^ z)))

#define SHA1M_A 0x67452301u
#define SHA1M_B 0xefcdab89u
#define SHA1M_C 0x98badcfeu
#define SHA1M_D 0x10325476u
#define SHA1M_E 0xc3d2e1f0u

#define SHA1C00 0x5a827999u
#define SHA1C01 0x6ed9eba1u
#define SHA1C02 0x8f1bbcdcu
#define SHA1C03 0xca62c1d6u

#define SHA1_STEP(f,a,b,c,d,e,x)    \
{                                   \
  e += K;                           \
  e += x;                           \
  e += f (b, c, d);                 \
  e += rotl32 (a,  5u);             \
  b  = rotl32 (b, 30u);             \
}

static void sha1_process2 (const unsigned int *W, unsigned int *digest)
{
  unsigned int A = digest[0];
  unsigned int B = digest[1];
  unsigned int C = digest[2];
  unsigned int D = digest[3];
  unsigned int E = digest[4];

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

  #undef K
  #define K SHA1C00

  SHA1_STEP (F1, A, B, C, D, E, w0_t);
  SHA1_STEP (F1, E, A, B, C, D, w1_t);
  SHA1_STEP (F1, D, E, A, B, C, w2_t);
  SHA1_STEP (F1, C, D, E, A, B, w3_t);
  SHA1_STEP (F1, B, C, D, E, A, w4_t);
  SHA1_STEP (F1, A, B, C, D, E, w5_t);
  SHA1_STEP (F1, E, A, B, C, D, w6_t);
  SHA1_STEP (F1, D, E, A, B, C, w7_t);
  SHA1_STEP (F1, C, D, E, A, B, w8_t);
  SHA1_STEP (F1, B, C, D, E, A, w9_t);
  SHA1_STEP (F1, A, B, C, D, E, wa_t);
  SHA1_STEP (F1, E, A, B, C, D, wb_t);
  SHA1_STEP (F1, D, E, A, B, C, wc_t);
  SHA1_STEP (F1, C, D, E, A, B, wd_t);
  SHA1_STEP (F1, B, C, D, E, A, we_t);
  SHA1_STEP (F1, A, B, C, D, E, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (F1, E, A, B, C, D, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (F1, D, E, A, B, C, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (F1, C, D, E, A, B, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (F1, B, C, D, E, A, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (F2, A, B, C, D, E, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (F2, E, A, B, C, D, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (F2, D, E, A, B, C, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (F2, C, D, E, A, B, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (F2, B, C, D, E, A, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (F2, A, B, C, D, E, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (F2, E, A, B, C, D, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (F2, D, E, A, B, C, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (F2, C, D, E, A, B, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (F2, B, C, D, E, A, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (F2, A, B, C, D, E, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (F2, E, A, B, C, D, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (F2, D, E, A, B, C, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (F2, C, D, E, A, B, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (F2, B, C, D, E, A, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (F2, A, B, C, D, E, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (F2, E, A, B, C, D, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (F2, D, E, A, B, C, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (F2, C, D, E, A, B, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (F2, B, C, D, E, A, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (F0, A, B, C, D, E, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (F0, E, A, B, C, D, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (F0, D, E, A, B, C, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (F0, C, D, E, A, B, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (F0, B, C, D, E, A, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (F0, A, B, C, D, E, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (F0, E, A, B, C, D, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (F0, D, E, A, B, C, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (F0, C, D, E, A, B, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (F0, B, C, D, E, A, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (F0, A, B, C, D, E, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (F0, E, A, B, C, D, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (F0, D, E, A, B, C, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (F0, C, D, E, A, B, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (F0, B, C, D, E, A, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (F0, A, B, C, D, E, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (F0, E, A, B, C, D, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (F0, D, E, A, B, C, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (F0, C, D, E, A, B, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (F0, B, C, D, E, A, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (F2, A, B, C, D, E, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (F2, E, A, B, C, D, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (F2, D, E, A, B, C, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (F2, C, D, E, A, B, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (F2, B, C, D, E, A, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (F2, A, B, C, D, E, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (F2, E, A, B, C, D, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (F2, D, E, A, B, C, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (F2, C, D, E, A, B, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (F2, B, C, D, E, A, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (F2, A, B, C, D, E, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (F2, E, A, B, C, D, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (F2, D, E, A, B, C, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (F2, C, D, E, A, B, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (F2, B, C, D, E, A, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (F2, A, B, C, D, E, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (F2, E, A, B, C, D, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (F2, D, E, A, B, C, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (F2, C, D, E, A, B, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (F2, B, C, D, E, A, wf_t);

  digest[0] += A;
  digest[1] += B;
  digest[2] += C;
  digest[3] += D;
  digest[4] += E;
}

static void F(__global const unsigned int *pass, const unsigned int pass_len, unsigned int *salt, const unsigned int salt_len, const unsigned int iter, __global unsigned int* hash, unsigned int hash_len)
{
    int plen=pass_len/4;
    if (mod(pass_len,4)) plen++;

    int slen=salt_len/4;
    if (mod(salt_len,4)) slen++;

    __global unsigned int* p = hash;

    unsigned int ipad[16];
    ipad[0x0]=0x36363636;
    ipad[0x1]=0x36363636;
    ipad[0x2]=0x36363636;
    ipad[0x3]=0x36363636;
    ipad[0x4]=0x36363636;
    ipad[0x5]=0x36363636;
    ipad[0x6]=0x36363636;
    ipad[0x7]=0x36363636;
    ipad[0x8]=0x36363636;
    ipad[0x9]=0x36363636;
    ipad[0xA]=0x36363636;
    ipad[0xB]=0x36363636;
    ipad[0xC]=0x36363636;
    ipad[0xD]=0x36363636;
    ipad[0xE]=0x36363636;
    ipad[0xF]=0x36363636;

    unsigned int opad[16];
    opad[0x0]=0x5C5C5C5C;
    opad[0x1]=0x5C5C5C5C;
    opad[0x2]=0x5C5C5C5C;
    opad[0x3]=0x5C5C5C5C;
    opad[0x4]=0x5C5C5C5C;
    opad[0x5]=0x5C5C5C5C;
    opad[0x6]=0x5C5C5C5C;
    opad[0x7]=0x5C5C5C5C;
    opad[0x8]=0x5C5C5C5C;
    opad[0x9]=0x5C5C5C5C;
    opad[0xA]=0x5C5C5C5C;
    opad[0xB]=0x5C5C5C5C;
    opad[0xC]=0x5C5C5C5C;
    opad[0xD]=0x5C5C5C5C;
    opad[0xE]=0x5C5C5C5C;
    opad[0xF]=0x5C5C5C5C;

    for (int m=0;m<plen && m<16;m++)
    {
        ipad[m]^=SWAP(pass[m]);
        opad[m]^=SWAP(pass[m]);
    }

    // precompute ipad
            unsigned int stateipad[5]={0};
            stateipad[0] = 0x67452301;
            stateipad[1] = 0xefcdab89;
            stateipad[2] = 0x98badcfe;
            stateipad[3] = 0x10325476;
            stateipad[4] = 0xc3d2e1f0;

            //->sha256_update(state,W,ilenor,wposr,ipad,0x40);
            unsigned int W[0x10]={0};
            W[0]=ipad[0];
            W[1]=ipad[1];
            W[2]=ipad[2];
            W[3]=ipad[3];
            W[4]=ipad[4];
            W[5]=ipad[5];
            W[6]=ipad[6];
            W[7]=ipad[7];
            W[8]=ipad[8];
            W[9]=ipad[9];
            W[10]=ipad[10];
            W[11]=ipad[11];
            W[12]=ipad[12];
            W[13]=ipad[13];
            W[14]=ipad[14];
            W[15]=ipad[15];
            sha1_process2(W,stateipad);

        // precompute ipad
            unsigned int stateopad[5]={0};
            stateopad[0] = 0x67452301;
            stateopad[1] = 0xefcdab89;
            stateopad[2] = 0x98badcfe;
            stateopad[3] = 0x10325476;
            stateopad[4] = 0xc3d2e1f0;

            //->sha1_update(state,W,ilenor,wposr,ipad,0x40);
            W[0]=opad[0];
            W[1]=opad[1];
            W[2]=opad[2];
            W[3]=opad[3];
            W[4]=opad[4];
            W[5]=opad[5];
            W[6]=opad[6];
            W[7]=opad[7];
            W[8]=opad[8];
            W[9]=opad[9];
            W[10]=opad[10];
            W[11]=opad[11];
            W[12]=opad[12];
            W[13]=opad[13];
            W[14]=opad[14];
            W[15]=opad[15];
            sha1_process2(W,stateopad);

    unsigned int counter = 1;
    unsigned int state[5]={0};

    unsigned int tkeylen=hash_len;
  unsigned int cplen=0;
  while(tkeylen>0)
    {
    if(tkeylen > 20) cplen = 20;
    else cplen=tkeylen;

        //hmac_sha1_init(state,W,ileno,wpos,ipad,opad,pwd);
        //->sha1_init(state,W,ileno,wpos);
        //->sha1_update(state,W,ileno,wpos,ipad,0x40);
        state[0] = stateipad[0];
        state[1] = stateipad[1];
        state[2] = stateipad[2];
        state[3] = stateipad[3];
        state[4] = stateipad[4];
        //hmac_sha1_update(state,W,ileno,wpos,ipad,opad,salt,salt_len);
        //->sha1_update(state,W,ileno,wpos,salt,salt_len);
        //hmac_sha1_update(state,W,ileno,wpos,ipad,opad,itmp,4);
        //->sha1_update(state,W,ileno,wpos,itmp,4);
        W[0]=0;
        W[1]=0;
        W[2]=0;
        W[3]=0;
        W[4]=0;
        W[5]=0;
        W[6]=0;
        W[7]=0;
        W[8]=0;
        W[9]=0;
        W[10]=0;
        W[11]=0;
        W[12]=0;
        W[13]=0;
        W[14]=0;
        for (int m=0;m<slen;m++)
        {
            W[m]=SWAP(salt[m]);
        }
        W[slen]=counter;

        unsigned int padding=0x80<<(((salt_len+4)-((salt_len+4)/4*4))*8);
        W[((mod((salt_len+4),(16*4)))/4)]|=SWAP(padding);
            // Let's add length
        W[0x0F]=(0x40+(salt_len+4))*8;

        //W[slen+1]=0x80000000;
        //W[15]=0x54*8;
        //hmac_sha1_final(state,W,ileno,ipad,opad,digtmp);
        //->sha1_finish(state,W,ileno,&opad[0x10]);
        sha1_process2(W,state);

        //sha1(opad,0x54,digtmp);
    //->sha1_init(state,W,ileno,wpos);
    //->sha1_update(state,W,ileno,wpos,opad,0x54);
    //->sha1_finish(state,W,ileno,digtmp);

        W[0]=state[0];
        W[1]=state[1];
        W[2]=state[2];
        W[3]=state[3];
        W[4]=state[4];
        W[5]=0x80000000;
        W[6]=0x0;
        W[7]=0x0;
        W[8]=0x0;
        W[9]=0;
        W[10]=0;
        W[11]=0;
        W[12]=0;
        W[13]=0;
        W[14]=0;
        W[15]=0x54*8;

        state[0]=stateopad[0];
        state[1]=stateopad[1];
        state[2]=stateopad[2];
        state[3]=stateopad[3];
        state[4]=stateopad[4];

        //sha256_finish(state,W,ileno,digtmp);
        sha1_process2(W,state);

        p[0]=W[0]=state[0];
        p[1]=W[1]=state[1];
        p[2]=W[2]=state[2];
        p[3]=W[3]=state[3];
        p[4]=W[4]=state[4];

        for(int j = 1; j < iter; j++)
        {
            //hmac_sha1(pwd,digtmp,32,digtmp);
            //->sha1_init(state,W,ilenor,wposr);
            //->sha1_update(state,W,ilenor,wposr,digtmp,32);
            //->sha1_finish(state,W,ileno,&opad[0x10]);

            W[5]=0x80000000; //Padding
            W[6]=0;
            W[7]=0;
            W[8]=0;
            W[9]=0;
            W[10]=0;
            W[11]=0;
            W[12]=0;
            W[13]=0;
            W[14]=0;
            W[15]=0x54*8;
            state[0] = stateipad[0];
            state[1] = stateipad[1];
            state[2] = stateipad[2];
            state[3] = stateipad[3];
            state[4] = stateipad[4];
            sha1_process2(W,state);

            unsigned int M[0x10]={0};
            M[0]=state[0];
            M[1]=state[1];
            M[2]=state[2];
            M[3]=state[3];
            M[4]=state[4];
            M[5]=0x80000000; //Padding
            M[6]=0;
            M[7]=0;
            M[8]=0;
            M[9]=0;
            M[10]=0;
            M[11]=0;
            M[12]=0;
            M[13]=0;
            M[14]=0;
            M[15]=0x54*8;

            //->sha1_init(state,W,ilenor,wposr);
            //->sha1_update(state,W,ilenor,wposr,opad,0x60);
            state[0] = stateopad[0];
            state[1] = stateopad[1];
            state[2] = stateopad[2];
            state[3] = stateopad[3];
            state[4] = stateopad[4];

            //->sha1_finish(state,W,ilenor,digtmp);
            sha1_process2(M,state);

            W[0]=state[0];
            W[1]=state[1];
            W[2]=state[2];
            W[3]=state[3];
            W[4]=state[4];

            p[0] ^= state[0];
            p[1] ^= state[1];
            p[2] ^= state[2];
            p[3] ^= state[3];
            p[4] ^= state[4];
        }

        p[0]=SWAP(p[0]);
        p[1]=SWAP(p[1]);
        p[2]=SWAP(p[2]);
        p[3]=SWAP(p[3]);
        p[4]=SWAP(p[4]);

        tkeylen-= cplen;
        counter++;
        p+= cplen/4;
    }
    return;
}


__kernel void pbkdf2(__global inbuf *inbuffer, __global const saltbuf *saltbuffer, __global outbuf *outbuffer,
    __private unsigned int iters, __private unsigned int dkLen_bytes)
{

    unsigned int idx = get_global_id(0);
    word pwdLen_bytes = inbuffer[idx].length;
    __global const word *pwdBuffer = inbuffer[idx].buffer;
    __global word *currOutBuffer = outbuffer[idx].buffer;

    // Copy salt so that we can write our integer into the last 4 bytes
    word personal_salt[32/4] = {0};
    personal_salt[0] = saltbuffer[0].buffer[0];
    personal_salt[1] = saltbuffer[0].buffer[1];
    personal_salt[2] = saltbuffer[0].buffer[2];
    personal_salt[3] = saltbuffer[0].buffer[3];
    personal_salt[4] = saltbuffer[0].buffer[4];
    personal_salt[5] = saltbuffer[0].buffer[5];
    personal_salt[6] = saltbuffer[0].buffer[6];
    personal_salt[7] = saltbuffer[0].buffer[7];

    F(pwdBuffer, pwdLen_bytes, personal_salt, saltbuffer[0].length, iters, currOutBuffer,32);
}
