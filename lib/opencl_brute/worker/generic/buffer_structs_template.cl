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
#define wordSize <word_size>

// Practical sizes of buffers, in words.
#define inBufferSize ceilDiv(<inBufferSize_bytes>, wordSize)
#define outBufferSize ceilDiv(<outBufferSize_bytes>, wordSize)
#define pwdBufferSize ceilDiv(<pwdBufferSize_bytes>, wordSize)
#define saltBufferSize ceilDiv(<saltBufferSize_bytes>, wordSize)
#define ctBufferSize ceilDiv(<ctBufferSize_bytes>, wordSize)

// 
#define hashBlockSize_bytes ceilDiv(<hashBlockSize_bits>, 8) /* Needs to be a multiple of 4, or 8 when we work with unsigned longs */
#define hashDigestSize_bytes ceilDiv(<hashDigestSize_bits>, 8)

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

// Password buffer, used by pbkdf2 & pbe
typedef struct {
    word length; // in bytes
    word buffer[pwdBufferSize];
} pwdbuf;

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
#endif