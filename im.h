/*
 * LIMITATIONS: This library only works on windows and unix-like (unix,
 * linux, FreeBSD, OpenBSD, etc...) operating systems. And it only works
 * on little endian systems.(x86, x86_64, ARM)
 *
*/

#ifndef IM_H
#define IM_H

#ifdef __cplusplus
extern "C" {
#endif

#define IM_API extern
IM_API unsigned char *im_load(const char *image_path, int *width, int *height, int *number_of_channels, int desired_channels);
IM_API void im_set_flip_vertically_on_load(int flag);

#ifdef __cplusplus
}
#endif

#endif

#ifdef IM_IMPLEMENTATION
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <limits.h>
#include <float.h>

#ifdef __linux
#include <unistd.h>
#endif

#include <fcntl.h>
#include <sys/stat.h>

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
    #define IM_X86 1
    #include <emmintrin.h>
    #if defined(_MSC_VER)
        #include <intrin.h>
    #elif defined(__GNUC__) || defined(__clang__)
        #include <cpuid.h>
    #endif
#endif

#if defined(__arm__) || defined(__aarch64__) || defined(_M_ARM) || defined(_M_ARM64)
    #define IM_ARM 1
    #if defined(__ARM_NEON) || defined(__ARM_NEON__) || defined(__aarch64__) || defined(_M_ARM64)
        #define IM_CAN_COMPILE_NEON 1
        #include <arm_neon.h>
    #endif
    #if defined(__linux__)
        #include <sys/auxv.h>
        #if defined(__aarch64__)
            #include <asm/hwcap.h>
        #else
            #ifndef HWCAP_NEON
                #define HWCAP_NEON (1 << 12)
            #endif
        #endif
    #elif defined(_WIN32)
        #include <windows.h>
    #endif
#endif

#ifndef _STDINT_H
/* 8-bit type */
/* according to the c standard, char is guarunteed to be 1 byte. */
#if UCHAR_MAX == 0xFF
typedef unsigned char  uint8_t;
typedef signed   char  int8_t;
#else
#error "No 8-bit type available on this platform."
#endif /* 8-bit type */

/* 16-bit type */
/* according to the c standard, short is guarunteed to be at least 2 bytes, since it has to be at least bigger than a char. */
#if USHRT_MAX == 0xFFFF
typedef unsigned short uint16_t;
typedef signed   short int16_t;
#elif UINT_MAX == 0xFFFF
typedef unsigned int   uint16_t;
typedef signed   int   int16_t;
#else
#error "No 16-bit type available on this platform."
#endif /* 16-bit types */

/* 32-bit type */
#if UINT_MAX == 0xFFFFFFFFUL
typedef unsigned int uint32_t;
typedef signed   int int32_t;
#elif ULONG_MAX == 0xFFFFFFFFUL
typedef unsigned long  uint32_t;
typedef signed   long  int32_t;
#else
#error "No 32-bit type available on this platform."
#endif /* 32 bit types */

#if ULONG_MAX == 0xFFFFFFFFFFFFFFFFUL
typedef unsigned long uint64_t;
typedef signed   long int64_t;
#elif defined(ULLONG_MAX) && ULLONG_MAX == 0xFFFFFFFFFFFFFFFFULL
typedef unsigned long long uint64_t;
typedef signed   long long int64_t;
#else
#error "No 64-bit type available on this platform."
#endif

#endif

/* The IM_ERR macro does not work if you try to split up the macro across multiple lines */
#ifndef IM_NO_ERRORS
#define IM_ERROR(...) \
    do { \
        printf("[ERROR] "); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } while(0)
#define IM_ERR(...) IM_ERROR(__VA_ARGS__)
#else
#define IM_ERROR(...) ((void)0)
#define IM_ERR(...)((void)0)
#endif

#ifdef IM_DEBUG
#define IM_INFORMATION(...) \
    do { \
        printf("[INFO] "); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } while(0)
#define IM_INFO(...) IM_INFORMATION(__VA_ARGS__)
#else
#define IM_INFO(...) ((void)0)
#define IM_INFORMATION(...)((void)0)
#endif

#define PNG_SIG_LEN 8
#define PNG_CHUNK_TYPE_LEN 4
#define PNG_CHUNK_DATA_LEN 4
#define PNG_CHUNK_CRC_LEN 4

#define STR_TO_UINT_LE(a,b,c,d) \
    (((uint32_t)(a))       | \
     ((uint32_t)(b) << 8)  | \
     ((uint32_t)(c) << 16) | \
     ((uint32_t)(d) << 24))

typedef int im_bool;
#define im_true 1
#define im_false 0

typedef enum {
    GRAYSCALE = 0,
    RGB = 2,
    PALETTE = 3, /* Special colour mode where you use a pre-defined palette in order to choose your colours. And each pixel is a palette index. */
    GRAYSCALE_A = 4,
    RGBA = 6
}im_png_ihdr_color_types;

typedef enum {
    UNCOMPRESSED, // 0
    FIXED_HUFFMAN, // 1
    DYNAMIC_HUFFMAN, // 2
    RESERVED
}im_png_compression_types;

typedef enum {
    /* IHDR has to be the first chunk in the file. */
    CHUNK_IHDR = STR_TO_UINT_LE('I','H','D','R'),

    /* these ones have to appear in the file before PLTE and IDAT */
    CHUNK_cHRM = STR_TO_UINT_LE('c','H','R','M'),
    CHUNK_iCCP = STR_TO_UINT_LE('i','C','C','P'),
    CHUNK_sBIT = STR_TO_UINT_LE('s','B','I','T'),
    CHUNK_sRGB = STR_TO_UINT_LE('s','R','G','B'),

    /* PLTE is optional, but has to appear after IHDR */
    CHUNK_PLTE = STR_TO_UINT_LE('P','L','T','E'),

    CHUNK_bKGD = STR_TO_UINT_LE('b','K','G','D'),
    CHUNK_hIST = STR_TO_UINT_LE('h','I','S','T'),
    CHUNK_tRNS = STR_TO_UINT_LE('t','R','N','S'),
    CHUNK_pHYs = STR_TO_UINT_LE('p','H','Y','s'),
    CHUNK_sPLT = STR_TO_UINT_LE('s','P','L','T'),

    /* IDAT (has to appear after PLTE if PLTE is present, if it's not present, it has to appear after IHDR). */
    CHUNK_IDAT = STR_TO_UINT_LE('I','D','A','T'),

    CHUNK_iTXt = STR_TO_UINT_LE('i','T','X','t'),
    CHUNK_tEXt = STR_TO_UINT_LE('t','E','X','t'),
    CHUNK_zTXt = STR_TO_UINT_LE('z','T','X','t'),
    CHUNK_tIME = STR_TO_UINT_LE('t','I','M','E'),
    CHUNK_gAMA = STR_TO_UINT_LE('g','A','M','A'),

    /* IEND has to appear after IDAT, and has to be the last chunk in the file. */
    CHUNK_IEND = STR_TO_UINT_LE('I','E','N','D')
}im_png_chunk_types_le;

typedef struct{
    unsigned char *png_file;
    unsigned char *at; /* newer variable used for parsing */
    unsigned char *end_of_file; /* we use at + end of file to figure out where we are, and where the end is so that we don't go over. */
    uint32_t width;
    uint32_t height;
    uint8_t channel_count; /* channels are called "samples" in the spec, but that's stupid, so I won't call them samples. */
    uint8_t bits_per_channel;
    uint8_t color_type;
    uint8_t compression_method;
    uint8_t filter_method;
    uint8_t interlace_method;
    im_bool first_ihdr;
    int idat_count;
    /* gamma */
    double gamma;
    /* chromaticity */
    double white_x;
    double white_y;
    double red_x;
    double red_y;
    double green_x;
    double green_y;
    double blue_x;
    double blue_y;

    /* background image */
    /* no alpha allowed for background images in the spec. */
    uint8_t bkgd_palette_idx;
    uint16_t bkgd_r;
    uint16_t bkgd_g;
    uint16_t bkgd_b;
    uint16_t bkgd_gray;

    /* time */
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
	
	/* ADD: palette support */
    uint8_t palette[256 * 3];  /* RGB palette, up to 256 entries */
    int palette_size;          /* number of palette entries */
	
    unsigned char *png_pixels; /* the actual pixels of the image, uncompressed. */
}im_png_info;

uint8_t im_png_sig[PNG_SIG_LEN] = {137, 80, 78, 71, 13, 10, 26, 10};

static int im_flip_vertically_flag = 0;

IM_API void im_set_flip_vertically_on_load(int flag) {
    im_flip_vertically_flag = flag;
}

/* Flip image data vertically (in-place) */
static void im_flip_vertically(unsigned char *data, int width, int height, int channels) {
    if (!data || height <= 1) return;
    
    size_t row_size = (size_t)width * channels;
    unsigned char *row_buffer = (unsigned char *)malloc(row_size);
    if (!row_buffer) return;
    
    int half_height = height / 2;
    for (int y = 0; y < half_height; y++) {
        unsigned char *top_row = data + (size_t)y * row_size;
        unsigned char *bottom_row = data + (size_t)(height - 1 - y) * row_size;
        
        /* Swap rows */
        memcpy(row_buffer, top_row, row_size);
        memcpy(top_row, bottom_row, row_size);
        memcpy(bottom_row, row_buffer, row_size);
    }
    
    free(row_buffer);
}
static int im_cpu_has_sse2 = -1;  /* -1 = not checked, 0 = no, 1 = yes */
static int im_cpu_has_neon = -1;

static void im_detect_cpu_features(void) {
    /* SSE2 detection for x86/x64 */
#ifdef IM_X86
    #if defined(_MSC_VER)
        int info[4];
        __cpuid(info, 1);
        im_cpu_has_sse2 = (info[3] & (1 << 26)) != 0;
    #elif defined(__GNUC__) || defined(__clang__)
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
            im_cpu_has_sse2 = (edx & (1 << 26)) != 0;
        } else {
            im_cpu_has_sse2 = 0;
        }
    #else
        im_cpu_has_sse2 = 0;
    #endif
#else
    im_cpu_has_sse2 = 0;
#endif

    /* NEON detection for ARM */
#ifdef IM_ARM
    #if defined(__aarch64__) || defined(_M_ARM64)
        /* NEON is mandatory on AArch64 */
        im_cpu_has_neon = 1;
    #elif defined(__linux__)
        unsigned long hwcap = getauxval(AT_HWCAP);
        im_cpu_has_neon = (hwcap & HWCAP_NEON) != 0;
    #elif defined(__APPLE__)
        /* NEON always available on Apple ARM chips */
        im_cpu_has_neon = 1;
    #elif defined(_WIN32)
        im_cpu_has_neon = IsProcessorFeaturePresent(PF_ARM_NEON_INSTRUCTIONS_AVAILABLE);
    #else
        im_cpu_has_neon = 0;
    #endif
#else
    im_cpu_has_neon = 0;
#endif
}

static uint8_t im_paeth_predictor(uint8_t a, uint8_t b, uint8_t c) {
    int p = (int)a + (int)b - (int)c;
    int pa = p > a ? p - a : a - p;
    int pb = p > b ? p - b : b - p;
    int pc = p > c ? p - c : c - p;
    if (pa <= pb && pa <= pc) return a;
    if (pb <= pc) return b;
    return c;
}

static void im_unfilter_sub_scalar(uint8_t *row, size_t rowbytes, size_t bpp) {
    for (size_t i = bpp; i < rowbytes; i++) {
        row[i] += row[i - bpp];
    }
}

static void im_unfilter_up_scalar(uint8_t *row, const uint8_t *prev, size_t rowbytes) {
    for (size_t i = 0; i < rowbytes; i++) {
        row[i] += prev[i];
    }
}

static void im_unfilter_avg_scalar(uint8_t *row, const uint8_t *prev, size_t rowbytes, size_t bpp) {
    size_t i = 0;
    for (; i < bpp; i++) {
        row[i] += prev[i] >> 1;
    }
    for (; i < rowbytes; i++) {
        row[i] += (row[i - bpp] + prev[i]) >> 1;
    }
}

static void im_unfilter_paeth_scalar(uint8_t *row, const uint8_t *prev, size_t rowbytes, size_t bpp) {
    size_t i = 0;
    for (; i < bpp; i++) {
        row[i] += prev[i];
    }
    for (; i < rowbytes; i++) {
        row[i] += im_paeth_predictor(row[i - bpp], prev[i], prev[i - bpp]);
    }
}

/* ============================================================================
 * SSE2 IMPLEMENTATIONS
 * ============================================================================ */

#ifdef IM_X86

static void im_unfilter_up_sse2(uint8_t *row, const uint8_t *prev, size_t rowbytes) {
    size_t i = 0;
    for (; i + 16 <= rowbytes; i += 16) {
        __m128i r = _mm_loadu_si128((__m128i*)(row + i));
        __m128i p = _mm_loadu_si128((__m128i*)(prev + i));
        _mm_storeu_si128((__m128i*)(row + i), _mm_add_epi8(r, p));
    }
    for (; i < rowbytes; i++) {
        row[i] += prev[i];
    }
}

static void im_unfilter_sub_3bpp_sse2(uint8_t *row, size_t rowbytes) {
    if (rowbytes < 3) return;
    size_t i = 3;
    
    /* Unroll 4 pixels at a time */
    while (i + 12 <= rowbytes) {
        row[i+0] += row[i-3]; row[i+1] += row[i-2]; row[i+2] += row[i-1];
        row[i+3] += row[i+0]; row[i+4] += row[i+1]; row[i+5] += row[i+2];
        row[i+6] += row[i+3]; row[i+7] += row[i+4]; row[i+8] += row[i+5];
        row[i+9] += row[i+6]; row[i+10]+= row[i+7]; row[i+11]+= row[i+8];
        i += 12;
    }
    for (; i < rowbytes; i++) {
        row[i] += row[i - 3];
    }
}

static void im_unfilter_sub_4bpp_sse2(uint8_t *row, size_t rowbytes) {
    if (rowbytes < 4) return;
    
    size_t i = 4;
    __m128i prev = _mm_cvtsi32_si128(*(int*)row);
    
    while (i + 16 <= rowbytes) {
        __m128i x = _mm_loadu_si128((__m128i*)(row + i));
        
        /* Add carry from previous chunk (prev has last pixel in element 0) */
        x = _mm_add_epi8(x, prev);
        
        /* Prefix sum for 4-byte elements */
        x = _mm_add_epi8(x, _mm_slli_si128(x, 4));
        x = _mm_add_epi8(x, _mm_slli_si128(x, 8));
        
        _mm_storeu_si128((__m128i*)(row + i), x);
        prev = _mm_srli_si128(x, 12);
        i += 16;
    }
    
    for (; i < rowbytes; i++) {
        row[i] += row[i - 4];
    }
}

static void im_unfilter_avg_4bpp_sse2(uint8_t *row, const uint8_t *prev, size_t rowbytes) {
    if (rowbytes < 4) return;
    
    row[0] += prev[0] >> 1;
    row[1] += prev[1] >> 1;
    row[2] += prev[2] >> 1;
    row[3] += prev[3] >> 1;
    
    size_t i = 4;
    
    while (i + 4 <= rowbytes) {
        __m128i left = _mm_cvtsi32_si128(*(int*)(row + i - 4));
        __m128i up = _mm_cvtsi32_si128(*(int*)(prev + i));
        __m128i cur = _mm_cvtsi32_si128(*(int*)(row + i));
        
        /* (a+b)>>1 = ((a^b)>>1) + (a&b) */
        __m128i xored = _mm_xor_si128(left, up);
        __m128i anded = _mm_and_si128(left, up);
        __m128i avg = _mm_add_epi8(
            _mm_srli_epi16(_mm_and_si128(xored, _mm_set1_epi8((char)0xFE)), 1),
            anded);
        
        cur = _mm_add_epi8(cur, avg);
        *(int*)(row + i) = _mm_cvtsi128_si32(cur);
        i += 4;
    }
    
    for (; i < rowbytes; i++) {
        row[i] += (row[i - 4] + prev[i]) >> 1;
    }
}

static void im_unfilter_paeth_4bpp_sse2(uint8_t *row, const uint8_t *prev, size_t rowbytes) {
    if (rowbytes < 4) return;
    
    row[0] += prev[0];
    row[1] += prev[1];
    row[2] += prev[2];
    row[3] += prev[3];
    
    size_t i = 4;
    
    while (i + 4 <= rowbytes) {
        __m128i a = _mm_cvtsi32_si128(*(int*)(row + i - 4));
        __m128i b = _mm_cvtsi32_si128(*(int*)(prev + i));
        __m128i c = _mm_cvtsi32_si128(*(int*)(prev + i - 4));
        __m128i cur = _mm_cvtsi32_si128(*(int*)(row + i));
        
        __m128i zero = _mm_setzero_si128();
        __m128i a16 = _mm_unpacklo_epi8(a, zero);
        __m128i b16 = _mm_unpacklo_epi8(b, zero);
        __m128i c16 = _mm_unpacklo_epi8(c, zero);
        
        __m128i p = _mm_sub_epi16(_mm_add_epi16(a16, b16), c16);
        
        __m128i pa = _mm_sub_epi16(p, a16);
        __m128i pb = _mm_sub_epi16(p, b16);
        __m128i pc = _mm_sub_epi16(p, c16);
        
        pa = _mm_max_epi16(pa, _mm_sub_epi16(zero, pa));
        pb = _mm_max_epi16(pb, _mm_sub_epi16(zero, pb));
        pc = _mm_max_epi16(pc, _mm_sub_epi16(zero, pc));
        
        __m128i pa_le_pb = _mm_or_si128(_mm_cmplt_epi16(pa, pb), _mm_cmpeq_epi16(pa, pb));
        __m128i pa_le_pc = _mm_or_si128(_mm_cmplt_epi16(pa, pc), _mm_cmpeq_epi16(pa, pc));
        __m128i pb_le_pc = _mm_or_si128(_mm_cmplt_epi16(pb, pc), _mm_cmpeq_epi16(pb, pc));
        
        __m128i sel_a = _mm_and_si128(pa_le_pb, pa_le_pc);
        __m128i not_sel_a = _mm_andnot_si128(sel_a, _mm_set1_epi16(-1));
        
        __m128i result = _mm_or_si128(
            _mm_and_si128(sel_a, a16),
            _mm_and_si128(not_sel_a,
                _mm_or_si128(
                    _mm_and_si128(pb_le_pc, b16),
                    _mm_andnot_si128(pb_le_pc, c16))));
        
        __m128i paeth8 = _mm_packus_epi16(result, result);
        cur = _mm_add_epi8(cur, paeth8);
        *(int*)(row + i) = _mm_cvtsi128_si32(cur);
        i += 4;
    }
    
    for (; i < rowbytes; i++) {
        row[i] += im_paeth_predictor(row[i - 4], prev[i], prev[i - 4]);
    }
}

#endif /* IM_X86 */

/* ============================================================================
 * NEON IMPLEMENTATIONS
 * ============================================================================ */

#ifdef IM_CAN_COMPILE_NEON

static void im_unfilter_up_neon(uint8_t *row, const uint8_t *prev, size_t rowbytes) {
    size_t i = 0;
    for (; i + 16 <= rowbytes; i += 16) {
        uint8x16_t r = vld1q_u8(row + i);
        uint8x16_t p = vld1q_u8(prev + i);
        vst1q_u8(row + i, vaddq_u8(r, p));
    }
    for (; i < rowbytes; i++) {
        row[i] += prev[i];
    }
}

static void im_unfilter_sub_3bpp_neon(uint8_t *row, size_t rowbytes) {
    im_unfilter_sub_scalar(row, rowbytes, 3);
}

static void im_unfilter_sub_4bpp_neon(uint8_t *row, size_t rowbytes) {
    if (rowbytes < 4) return;
    
    size_t i = 4;
    uint32_t prev_pixel = *(uint32_t*)row;
    
    while (i + 16 <= rowbytes) {
        uint8x16_t x = vld1q_u8(row + i);
        
        /* Add carry from previous chunk - prev_pixel goes in bytes 0-3 only */
        uint32x4_t prev_vec = vdupq_n_u32(0);
        prev_vec = vsetq_lane_u32(prev_pixel, prev_vec, 0);
        uint8x16_t carry = vreinterpretq_u8_u32(prev_vec);
        x = vaddq_u8(x, carry);
        
        /* Prefix sum for 4-byte elements (shift left, then add) */
        x = vaddq_u8(x, vextq_u8(vdupq_n_u8(0), x, 12));
        x = vaddq_u8(x, vextq_u8(vdupq_n_u8(0), x, 8));
        
        vst1q_u8(row + i, x);
        prev_pixel = vgetq_lane_u32(vreinterpretq_u32_u8(x), 3);
        i += 16;
    }
    
    for (; i < rowbytes; i++) {
        row[i] += row[i - 4];
    }
}

static void im_unfilter_avg_4bpp_neon(uint8_t *row, const uint8_t *prev, size_t rowbytes) {
    if (rowbytes < 4) return;
    
    row[0] += prev[0] >> 1;
    row[1] += prev[1] >> 1;
    row[2] += prev[2] >> 1;
    row[3] += prev[3] >> 1;
    
    size_t i = 4;
    
    while (i + 4 <= rowbytes) {
        uint8x8_t left = vreinterpret_u8_u32(vld1_dup_u32((uint32_t*)(row + i - 4)));
        uint8x8_t up = vreinterpret_u8_u32(vld1_dup_u32((uint32_t*)(prev + i)));
        uint8x8_t cur = vreinterpret_u8_u32(vld1_dup_u32((uint32_t*)(row + i)));
        
        uint8x8_t avg = vhadd_u8(left, up);
        cur = vadd_u8(cur, avg);
        
        vst1_lane_u32((uint32_t*)(row + i), vreinterpret_u32_u8(cur), 0);
        i += 4;
    }
    
    for (; i < rowbytes; i++) {
        row[i] += (row[i - 4] + prev[i]) >> 1;
    }
}

static void im_unfilter_paeth_4bpp_neon(uint8_t *row, const uint8_t *prev, size_t rowbytes) {
    if (rowbytes < 4) return;
    
    row[0] += prev[0];
    row[1] += prev[1];
    row[2] += prev[2];
    row[3] += prev[3];
    
    size_t i = 4;
    
    while (i + 4 <= rowbytes) {
        uint8x8_t a8 = vreinterpret_u8_u32(vld1_dup_u32((uint32_t*)(row + i - 4)));
        uint8x8_t b8 = vreinterpret_u8_u32(vld1_dup_u32((uint32_t*)(prev + i)));
        uint8x8_t c8 = vreinterpret_u8_u32(vld1_dup_u32((uint32_t*)(prev + i - 4)));
        uint8x8_t cur = vreinterpret_u8_u32(vld1_dup_u32((uint32_t*)(row + i)));
        
        int16x8_t a = vreinterpretq_s16_u16(vmovl_u8(a8));
        int16x8_t b = vreinterpretq_s16_u16(vmovl_u8(b8));
        int16x8_t c = vreinterpretq_s16_u16(vmovl_u8(c8));
        
        int16x8_t p = vsubq_s16(vaddq_s16(a, b), c);
        
        int16x8_t pa = vabsq_s16(vsubq_s16(p, a));
        int16x8_t pb = vabsq_s16(vsubq_s16(p, b));
        int16x8_t pc = vabsq_s16(vsubq_s16(p, c));
        
        uint16x8_t sel_a = vandq_u16(vcleq_s16(pa, pb), vcleq_s16(pa, pc));
        uint16x8_t sel_b = vcleq_s16(pb, pc);
        
        int16x8_t result = vbslq_s16(sel_a, a, vbslq_s16(sel_b, b, c));
        
        uint8x8_t paeth8 = vmovn_u16(vreinterpretq_u16_s16(result));
        cur = vadd_u8(cur, paeth8);
        
        vst1_lane_u32((uint32_t*)(row + i), vreinterpret_u32_u8(cur), 0);
        i += 4;
    }
    
    for (; i < rowbytes; i++) {
        row[i] += im_paeth_predictor(row[i - 4], prev[i], prev[i - 4]);
    }
}

#endif /* IM_CAN_COMPILE_NEON */

/* ============================================================================
 * RUNTIME DISPATCHERS
 * ============================================================================ */

static void im_unfilter_up(uint8_t *row, const uint8_t *prev, size_t rowbytes) {
#ifdef IM_X86
    if (im_cpu_has_sse2) {
        im_unfilter_up_sse2(row, prev, rowbytes);
        return;
    }
#endif
#ifdef IM_CAN_COMPILE_NEON
    if (im_cpu_has_neon) {
        im_unfilter_up_neon(row, prev, rowbytes);
        return;
    }
#endif
    im_unfilter_up_scalar(row, prev, rowbytes);
}

static void im_unfilter_sub(uint8_t *row, size_t rowbytes, size_t bpp) {
#ifdef IM_X86
    if (im_cpu_has_sse2) {
        if (bpp == 4) { im_unfilter_sub_4bpp_sse2(row, rowbytes); return; }
        if (bpp == 3) { im_unfilter_sub_3bpp_sse2(row, rowbytes); return; }
    }
#endif
#ifdef IM_CAN_COMPILE_NEON
    if (im_cpu_has_neon) {
        if (bpp == 4) { im_unfilter_sub_4bpp_neon(row, rowbytes); return; }
        if (bpp == 3) { im_unfilter_sub_3bpp_neon(row, rowbytes); return; }
    }
#endif
    im_unfilter_sub_scalar(row, rowbytes, bpp);
}

static void im_unfilter_avg(uint8_t *row, const uint8_t *prev, size_t rowbytes, size_t bpp) {
#ifdef IM_X86
    if (im_cpu_has_sse2 && bpp == 4) {
        im_unfilter_avg_4bpp_sse2(row, prev, rowbytes);
        return;
    }
#endif
#ifdef IM_CAN_COMPILE_NEON
    if (im_cpu_has_neon && bpp == 4) {
        im_unfilter_avg_4bpp_neon(row, prev, rowbytes);
        return;
    }
#endif
    im_unfilter_avg_scalar(row, prev, rowbytes, bpp);
}

static void im_unfilter_paeth(uint8_t *row, const uint8_t *prev, size_t rowbytes, size_t bpp) {
#ifdef IM_X86
    if (im_cpu_has_sse2 && bpp == 4) {
        im_unfilter_paeth_4bpp_sse2(row, prev, rowbytes);
        return;
    }
#endif
#ifdef IM_CAN_COMPILE_NEON
    if (im_cpu_has_neon && bpp == 4) {
        im_unfilter_paeth_4bpp_neon(row, prev, rowbytes);
        return;
    }
#endif
    im_unfilter_paeth_scalar(row, prev, rowbytes, bpp);
}

void *im_memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;

    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }

    return dest;
}

int im_memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *p1 = a;
    const unsigned char *p2 = b;
    size_t i;
    for (i = 0; i < n; i++) {
        if (p1[i] != p2[i])
            return (p1[i] < p2[i]) ? -1 : 1;
    }

    return 0;
}

unsigned char *im__read_entire_file(const char *file_path, size_t *bytes_read) {
#ifdef _WIN32
    wchar_t* wide_path = win32_utf8_to_utf16(file_path);
    HANDLE file = NULL;
    LARGE_INTEGER file_size;
    size_t total_size = 0;
    char *buffer = NULL;
    size_t total_read = 0;

    if (!wide_path) return NULL;
    
    file = CreateFileW(
        wide_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    free(wide_path);

    if (file == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    if (!GetFileSizeEx(file, &file_size)) {
        CloseHandle(file);
        return NULL;
    }

    if (file_size.QuadPart > LLONG_MAX) {
        CloseHandle(file);
        return NULL;
    }

    total_size = (size_t)file_size.QuadPart;
    buffer = (char *)malloc(total_size + 1);
    if (!buffer) {
        CloseHandle(file);
        return NULL;
    }

    while (total_read < total_size) {
        DWORD chunk = (DWORD)((total_size - total_read > MAXDWORD) ? MAXDWORD : (total_size - total_read));
        DWORD read_now = 0;

        if (!ReadFile(file, buffer + total_read, chunk, &read_now, NULL)) {
            free(buffer);
            CloseHandle(file);
            return NULL;
        }

        if (read_now == 0) break;

        total_read += read_now;
    }
    buffer[total_size] = '\0';
    CloseHandle(file);

    if (bytes_read)
        *bytes_read = total_read;

    return (unsigned char*)buffer;
#else
    struct stat st;
    size_t file_size;
    int fd;
    void *buffer;
    size_t n;
    if(stat(file_path, &st) != 0) return NULL;
    file_size = st.st_size;

    fd = open(file_path, O_RDONLY);
    if(fd < 0) return NULL;

    buffer = malloc(file_size);
    if(!buffer) { close(fd); return NULL; }

    n = read(fd, buffer, file_size);
    close(fd);
    if(n != (size_t)file_size) { free(buffer); return NULL; }

    *bytes_read = file_size;
    return (unsigned char*)buffer;
#endif
}

void im_print_bytes(void *bytes_in, size_t len) {
    uint8_t *bytes = bytes_in;
    for(size_t i = 0; i < len; i++) {
        printf("%u ", bytes[i]);
    }
    printf("\n");
}

uint32_t consume_uint32(unsigned char **at, unsigned char *end_of_file) {
    if(*at + sizeof(uint32_t) <= end_of_file) {
        uint32_t value;
        memcpy(&value, *at, sizeof(uint32_t));
        *at += sizeof(uint32_t);
        return value;
    }
    fprintf(stderr, "Error: %s(), will not read past end of file.\n", __func__);
    return 0;
}

uint16_t consume_uint16(unsigned char **at, unsigned char *end_of_file) {
    if(*at + sizeof(uint16_t) <= end_of_file) {
        uint16_t value;
        memcpy(&value, *at, sizeof(uint16_t));
        *at += sizeof(uint16_t);
        return value;
    }
    fprintf(stderr, "Error: %s(), will not read past end of file.\n", __func__);
    return 0;
}

uint8_t consume_uint8(unsigned char **at, unsigned char *end_of_file) {
    uint8_t *orig = (uint8_t*)(*at);
    if(*at + sizeof(uint8_t) <= end_of_file) {
        *at += sizeof(uint8_t);
        return *orig;
    }
    fprintf(stderr, "Error: %s(), will not read past end of file.", __func__);
    return *orig;
}

uint32_t consume_and_swap_uint32(unsigned char **at, unsigned char *end_of_file) {
    uint32_t value = consume_uint32(at, end_of_file);
    value = (value << 24) | ((value << 8) & 0x00FF0000) | ((value >> 8) & 0x0000FF00) | (value >> 24);
    return value;
}

uint16_t consume_and_swap_uint16(unsigned char **at, unsigned char *end_of_file) {
    uint16_t value = consume_uint16(at, end_of_file);
    value = value << 8 | value >> 8;
    return value;
}

uint16_t endian_swap_uint16(uint16_t *start) {
    uint32_t value = *start;
    value = value << 8 | value >> 8;
    return value;
}

uint32_t endian_swap_uint32(uint32_t *start) {
    uint32_t value = *start;
    value = (value << 24) | ((value << 8) & 0x00FF0000) | ((value >> 8) & 0x0000FF00) | (value >> 24);
    return value;
}

void endian_swap(uint32_t *start) {
    uint32_t value = *start;
    value = (value << 24) | ((value << 8) & 0x00FF0000) | ((value >> 8) & 0x0000FF00) | (value >> 24);
    *start = value;
}

void *consume(unsigned char **at, unsigned char *end_of_file, size_t size) {
    void *orig = *at;
    if(*at + size <= end_of_file) {
        *at += size;
        return orig;
    }
    fprintf(stderr, "Error: %s(), will not read past end of file.", __func__);
    return orig;
}

// this function simply assumes that you will pass in the start of the uint32_t using the at.
void *consume_and_endian_swap(unsigned char **at, unsigned char *end_of_file, size_t size) {
    void *value = consume(at, end_of_file, size);
    endian_swap(value);
    return value;
}

size_t im_ceil(size_t x, size_t y) {
    return (x + y - 1) / y;
}

typedef struct {
    uint32_t length;
    uint32_t chunk_type;
}im_png_chunk_header;

typedef struct {
    uint32_t crc;
}im_png_footer;

void im_png_parse_chunk_PLTE(im_png_info *info) {
    im_png_chunk_header header = *(im_png_chunk_header*)consume(&info->at, info->end_of_file, sizeof(im_png_chunk_header));
    endian_swap((uint32_t*)&header);

    /* PLTE length must be divisible by 3 (RGB triplets) */
    if (header.length % 3 != 0 || header.length > 256 * 3) {
        IM_ERR("Invalid PLTE chunk length: %u", header.length);
        consume(&info->at, info->end_of_file, header.length);
        consume_uint32(&info->at, info->end_of_file);
        return;
    }

    info->palette_size = header.length / 3;
    
    /* Read palette entries (already in RGB order) */
    for (int i = 0; i < info->palette_size; i++) {
        info->palette[i * 3 + 0] = consume_uint8(&info->at, info->end_of_file); /* R */
        info->palette[i * 3 + 1] = consume_uint8(&info->at, info->end_of_file); /* G */
        info->palette[i * 3 + 2] = consume_uint8(&info->at, info->end_of_file); /* B */
    }

    IM_INFO("PLTE chunk: %d palette entries", info->palette_size);

    /* Skip CRC */
    consume_uint32(&info->at, info->end_of_file);
}
static unsigned char *im_png_expand_palette(im_png_info *info) {
    size_t pixel_count = (size_t)info->width * info->height;
    unsigned char *rgb_pixels = (unsigned char *)malloc(pixel_count * 3);
    
    if (!rgb_pixels) {
        IM_ERR("Failed to allocate memory for palette expansion");
        return NULL;
    }
    
    unsigned char *src = info->png_pixels;
    unsigned char *dst = rgb_pixels;
    
    if (info->bits_per_channel == 8) {
        /* 8-bit palette indices */
        for (size_t i = 0; i < pixel_count; i++) {
            uint8_t idx = src[i];
            if (idx >= info->palette_size) idx = 0;
            dst[i * 3 + 0] = info->palette[idx * 3 + 0];
            dst[i * 3 + 1] = info->palette[idx * 3 + 1];
            dst[i * 3 + 2] = info->palette[idx * 3 + 2];
        }
    } else if (info->bits_per_channel == 4) {
        /* 4-bit palette indices (2 per byte) */
        size_t src_idx = 0;
        for (size_t i = 0; i < pixel_count; i++) {
            uint8_t idx;
            if (i % 2 == 0) {
                idx = (src[src_idx] >> 4) & 0x0F;
            } else {
                idx = src[src_idx] & 0x0F;
                src_idx++;
            }
            if (idx >= info->palette_size) idx = 0;
            dst[i * 3 + 0] = info->palette[idx * 3 + 0];
            dst[i * 3 + 1] = info->palette[idx * 3 + 1];
            dst[i * 3 + 2] = info->palette[idx * 3 + 2];
        }
    } else if (info->bits_per_channel == 2) {
        /* 2-bit palette indices (4 per byte) */
        size_t src_idx = 0;
        for (size_t i = 0; i < pixel_count; i++) {
            int shift = 6 - (i % 4) * 2;
            uint8_t idx = (src[src_idx] >> shift) & 0x03;
            if ((i % 4) == 3) src_idx++;
            if (idx >= info->palette_size) idx = 0;
            dst[i * 3 + 0] = info->palette[idx * 3 + 0];
            dst[i * 3 + 1] = info->palette[idx * 3 + 1];
            dst[i * 3 + 2] = info->palette[idx * 3 + 2];
        }
    } else if (info->bits_per_channel == 1) {
        /* 1-bit palette indices (8 per byte) */
        size_t src_idx = 0;
        for (size_t i = 0; i < pixel_count; i++) {
            int shift = 7 - (i % 8);
            uint8_t idx = (src[src_idx] >> shift) & 0x01;
            if ((i % 8) == 7) src_idx++;
            if (idx >= info->palette_size) idx = 0;
            dst[i * 3 + 0] = info->palette[idx * 3 + 0];
            dst[i * 3 + 1] = info->palette[idx * 3 + 1];
            dst[i * 3 + 2] = info->palette[idx * 3 + 2];
        }
    }
    
    return rgb_pixels;
}

void im_png_parse_chunk_IHDR(im_png_info *info) {
    im_png_chunk_header header = *(im_png_chunk_header*)consume(&info->at, info->end_of_file, sizeof(im_png_chunk_header));
    endian_swap((uint32_t*)&header);

    IM_INFO("Length: %d\n", header.length);
    if(header.length != 13u){
        IM_ERR("Length section of ihdr chunk is not 13.");
    }

    if(!info->first_ihdr) IM_ERR("Multiple IHDR.");

    info->width = consume_and_swap_uint32(&info->at, info->end_of_file);
    info->height = consume_and_swap_uint32(&info->at, info->end_of_file);
    info->bits_per_channel = consume_uint8(&info->at, info->end_of_file);
    info->color_type = consume_uint8(&info->at, info->end_of_file);
    info->compression_method = consume_uint8(&info->at, info->end_of_file);
    info->filter_method = consume_uint8(&info->at, info->end_of_file);
    info->interlace_method = consume_uint8(&info->at, info->end_of_file);

    consume_uint32(&info->at, info->end_of_file);

#ifndef IM_NO_ERRORS
    if(info->color_type == 1 || info->color_type > 6) {
        IM_ERR("Invalid color type. Expected 0, 2, 3, 4, or 6, got: %u", info->color_type);
    }

    switch(info->color_type) {
        case 0:
            if (info->bits_per_channel != 1 && info->bits_per_channel != 2 && info->bits_per_channel != 4 && info->bits_per_channel != 8 && info->bits_per_channel != 16) {
                IM_ERR("Invalid bit depth for color type 0. Expected 1, 2, 4, 8 or 16, got: %u", info->bits_per_channel);
            }
            break;
        case 3:
            if (info->bits_per_channel != 1 && info->bits_per_channel != 2 && info->bits_per_channel != 4 && info->bits_per_channel != 8) {
                IM_ERR("Invalid bit depth for color type 3. Expected 1, 2, 4 or 8, got: %u", info->bits_per_channel);
            }
            break;
        case 2:
        case 4:
        case 6:
            if (info->bits_per_channel != 8 && info->bits_per_channel != 16) {
                IM_ERR("Invalid bit depth for color type 6. Expected 8 or 16, got: %u", info->bits_per_channel);
            }
            break;
    }
    if (info->compression_method != 0) {
        IM_ERR("Compression method is supposed to be 0, but it's: %u.", info->compression_method);
    }
    if (info->filter_method != 0) {
        IM_ERR("Filter method is supposed to be 0, but it's %u.", info->filter_method);
    }
    if (info->interlace_method != 0 && info->interlace_method != 1) {
        IM_ERR("Interlace method is supposed to be 0 or 1, but it's %u.", info->interlace_method);
    }
#endif

    IM_INFO("width: %d\n", info->width);
    IM_INFO("height: %d\n", info->height);
    IM_INFO("bits_per_channel: %d\n", info->bits_per_channel);
    IM_INFO("color_type: %d\n", info->color_type);
    IM_INFO("compression_method: %d\n", info->compression_method);
    IM_INFO("filter_method: %d\n", info->filter_method);
    IM_INFO("interlace_method: %d\n", info->interlace_method);

    switch(info->color_type) {
        case RGB:
            info->channel_count = 3;
            break;
        case RGBA:
            info->channel_count = 4;
            break;
        case PALETTE:
            info->channel_count = 1; /* this is technically wrong, but multiply by zero bellow will result in an empty buffer */
            break;
        case GRAYSCALE:
            info->channel_count = 1;
            break;
        case GRAYSCALE_A:
            info->channel_count = 2;
            break;
    }
}

 void im_png_parse_chunk_gAMA(im_png_info *info) {
    im_png_chunk_header header = *(im_png_chunk_header*)consume(&info->at, info->end_of_file, sizeof(im_png_chunk_header));
    endian_swap((uint32_t*)&header);

    if(header.length != 4u){
        IM_ERR("Length section of gAMA chunk is not 4.");
    }

    uint32_t tmp  = consume_and_swap_uint32(&info->at, info->end_of_file);
    info->gamma = tmp / 100000.0;
    IM_INFO("gAMA chunk: gamma = %.5f\n", info->gamma);

    consume_uint32(&info->at, info->end_of_file);
}

void im_png_parse_chunk_cHRM(im_png_info *info) {
    im_png_chunk_header header = *(im_png_chunk_header*)consume(&info->at, info->end_of_file, sizeof(im_png_chunk_header));
    endian_swap((uint32_t*)&header);

    if(header.length != 32u){
        IM_ERR("Length section of cHRM chunk is not 32.");
    }

    uint32_t tmp;
    tmp = consume_and_swap_uint32(&info->at, info->end_of_file);
    info->white_x = tmp / 100000.0;
    tmp = consume_and_swap_uint32(&info->at, info->end_of_file);
    info->white_y = tmp / 100000.0;
    tmp = consume_and_swap_uint32(&info->at, info->end_of_file);
    info->red_x = tmp / 100000.0;
    tmp = consume_and_swap_uint32(&info->at, info->end_of_file);
    info->red_y = tmp / 100000.0;
    tmp = consume_and_swap_uint32(&info->at, info->end_of_file);
    info->green_x = tmp / 100000.0;
    tmp = consume_and_swap_uint32(&info->at, info->end_of_file);
    info->green_y = tmp / 100000.0;
    tmp = consume_and_swap_uint32(&info->at, info->end_of_file);
    info->blue_x = tmp / 100000.0;
    tmp = consume_and_swap_uint32(&info->at, info->end_of_file);
    info->blue_y = tmp / 100000.0;
    IM_INFO("white_x = %.5f\n", info->white_x);
    IM_INFO("white_y = %.5f\n", info->white_y);
    IM_INFO("red_x = %.5f\n", info->red_x);
    IM_INFO("red_y = %.5f\n", info->red_y);
    IM_INFO("green_x = %.5f\n", info->green_x);
    IM_INFO("green_y = %.5f\n", info->green_y);
    IM_INFO("blue_x = %.5f\n", info->blue_x);
    IM_INFO("blue_y = %.5f\n", info->blue_y);

    consume_uint32(&info->at, info->end_of_file);
}

void im_png_parse_chunk_bKGD(im_png_info *info) {
    im_png_chunk_header header = *(im_png_chunk_header*)consume(&info->at, info->end_of_file, sizeof(im_png_chunk_header));
    endian_swap((uint32_t*)&header);

    switch(info->color_type) {
        case 0:
        case 4: {
            #ifndef IM_NO_ERRORS
            if(header.length != 2u){
                IM_ERR("For color type %d, data len is supposed to be 2. data_len is: %d.", info->color_type, header.length);
            }
            #endif
            info->bkgd_gray = consume_uint16(&info->at, info->end_of_file);
            break;
        }
        case 2:
        case 6: {
            #ifndef IM_NO_ERRORS
            if(header.length != 6u){
                IM_ERR("For color type %d, data_len is supposed to be 6. data_len is: %d.", info->color_type, header.length);
            }
            #endif
            info->bkgd_r = consume_uint16(&info->at, info->end_of_file);
            info->bkgd_g = consume_uint16(&info->at, info->end_of_file);
            info->bkgd_b = consume_uint16(&info->at, info->end_of_file);
            break;
        }
        case 3: {
            #ifndef IM_NO_ERRORS
            if(header.length != 1u){
                IM_ERR("For color type 3, data_len is supposed to be 1. data_len is: %d.", header.length);
            }
            #endif
            info->bkgd_palette_idx = consume_uint8(&info->at, info->end_of_file);
            break;
        }
    }

    consume_uint32(&info->at, info->end_of_file);
}

void im_png_parse_chunk_tIME(im_png_info *info) {
    im_png_chunk_header header = *(im_png_chunk_header*)consume(&info->at, info->end_of_file, sizeof(im_png_chunk_header));
    endian_swap((uint32_t*)&header);

    if(header.length != 7u){
        IM_ERR("Length section of tIME chunk is not 13.");
    }

    info->year = consume_uint16(&info->at, info->end_of_file);
    info->month = consume_uint8(&info->at, info->end_of_file);
    info->day = consume_uint8(&info->at, info->end_of_file);
    info->hour = consume_uint8(&info->at, info->end_of_file);
    info->minute = consume_uint8(&info->at, info->end_of_file);
    info->second = consume_uint8(&info->at, info->end_of_file);

    consume_uint32(&info->at, info->end_of_file);
}

void im_png_parse_chunk_tEXt(im_png_info *info) {
    im_png_chunk_header header = *(im_png_chunk_header*)consume(&info->at, info->end_of_file, sizeof(im_png_chunk_header));
    endian_swap((uint32_t*)&header);

    unsigned char keyword[80] = {0};
    unsigned char at = 0;
    int counter = 0;
    do {
        if(counter >= 79) break;
        at = *(unsigned char*)consume(&info->at, info->end_of_file, 1);
        keyword[counter++] = at;
    } while(at != '\0');

    size_t text_len = header.length - counter;
    unsigned char *text = (unsigned char*)consume(&info->at, info->end_of_file, 1);
    consume(&info->at, info->end_of_file, text_len - 1);

    IM_INFO("%s %.*s\n", keyword, (int)text_len, text);

    consume_uint32(&info->at, info->end_of_file);
}

void im_png_parse_chunk_IEND(im_png_info *info) {
    im_png_chunk_header header = *(im_png_chunk_header*)consume(&info->at, info->end_of_file, sizeof(im_png_chunk_header));
    endian_swap((uint32_t*)&header);

    if(header.length != 0u){
        IM_ERR("Length section of IEND chunk is not 0.");
    }

    consume_uint32(&info->at, info->end_of_file);
}

unsigned char *get_next_chunk_type(im_png_info *info) {
    if(info->at + PNG_CHUNK_DATA_LEN < info->end_of_file) {
        return info->at + PNG_CHUNK_DATA_LEN;
    } else {
        IM_ERROR("Tried to read png chunk after end of file. Malformed PNG. Not going to load.");
        return NULL;
    }
}

/* Skip the chunk length(4 bytes), chunk type (4 bytes), chunk data, and CRC (4 bytes) */
void skip_chunk(im_png_info *info) {
    uint32_t length = consume_and_swap_uint32(&info->at, info->end_of_file);
    size_t bytes_needed_to_skip_chunk = PNG_CHUNK_TYPE_LEN + length + PNG_CHUNK_CRC_LEN;
    info->at += bytes_needed_to_skip_chunk;
}

void im_png_peek_bytes(im_png_info *info, void* buf, unsigned char *offset, const size_t bytes_to_read) {
    if(offset < info->end_of_file) {
        im_memcpy(buf, offset, bytes_to_read);
    } else {
        IM_ERR("Error: %s(): tried to read bytes past end of file, not going to read.", __func__);
    }
}

unsigned char* im_png_peek_next_chunk(im_png_info *info, unsigned char *current_chunk) {
    uint32_t data_length = 0;
    im_png_peek_bytes(info, &data_length, current_chunk, PNG_CHUNK_DATA_LEN);
    endian_swap(&data_length);
    IM_INFO("DATA LENGTH: %d\n", data_length);

    return current_chunk + PNG_CHUNK_DATA_LEN + PNG_CHUNK_TYPE_LEN + data_length + PNG_CHUNK_CRC_LEN;
}

void im_memset(void *buffer, int value, size_t count) {
    unsigned char *buf = buffer;
    for(size_t i = 0; i < count; i++) {
        buf[i] = value;
    }
}

typedef struct {
    const uint8_t *data;
    const uint8_t *end;
    uint64_t bits;
    int count;
} im_bitstream;

static void im_bs_init(im_bitstream *bs, const uint8_t *data, size_t len) {
    bs->data = data;
    bs->end = data + len;
    bs->bits = 0;
    bs->count = 0;
}

static void im_bs_refil(im_bitstream *bs) {
    while (bs->count <= 56 && bs->data < bs->end) {
        bs->bits |= (uint64_t)(*bs->data++) << bs->count;
        bs->count += 8;
    }
}

static uint32_t im_bs_peek(im_bitstream *bs, int n) {
    if (bs->count < n) im_bs_refil(bs);
    return bs->bits & ((1ULL << n) - 1);
}

static void im_bs_drop(im_bitstream *bs, int n) {
    bs->bits >>= n;
    bs->count -= n;
}

static uint32_t im_bs_read(im_bitstream *bs, int n) {
    uint32_t v = im_bs_peek(bs, n);
    im_bs_drop(bs, n);
    return v;
}

static void im_bs_align(im_bitstream *bs) {
    int discard = bs->count & 7;
    if (discard) im_bs_drop(bs, discard);
}

#define HUFF_FAST_BITS 9
#define HUFF_FAST_SIZE (1 << HUFF_FAST_BITS)  /* 512 */

/* Entry format: symbol (10 bits) | length (4 bits) | slow_flag (1 bit) */
#define HUFF_SYM_MASK  0x3FF    /* bits 0-9: symbol (max 1023) */
#define HUFF_LEN_SHIFT 10
#define HUFF_LEN_MASK  0xF      /* bits 10-13: length (1-15) */
#define HUFF_SLOW_FLAG 0x8000   /* bit 15: needs slow decode */

typedef struct {
    uint16_t fast[HUFF_FAST_SIZE];  /* Fast lookup for codes <= 9 bits */
    /* Slow path storage for codes > 9 bits */
    uint16_t slow_sym[320];         /* Symbol for each long code */
    uint8_t  slow_len[320];         /* Length for each long code */
    uint32_t slow_code[320];        /* Reversed code bits */
    int slow_count;                 /* Number of long codes */
    int max_length;                 /* Maximum code length */
} im_huffman_table;

/* Reverse the bottom n bits of a value */

/*
 * Build a fast Huffman lookup table from code lengths.
 * 
 * lengths: array of code lengths for each symbol (0 = symbol not used)
 * count: number of symbols
 * table: output table structure (must be zeroed before first call)
 *
 * Returns 0 on success, -1 on error.
 */

static uint32_t im_huff_bit_reverse(uint32_t val, int n) {
    uint32_t r = 0;
    for (int i = 0; i < n; i++) {
        r = (r << 1) | (val & 1);
        val >>= 1;
    }
    return r;
}

static int im_build_huffman_table(im_huffman_table *table, const uint8_t *lengths, int count) {
    int bl_count[16] = {0};
    int next_code[16] = {0};
    int max_len = 0;
    
    for (int i = 0; i < HUFF_FAST_SIZE; i++) table->fast[i] = 0;
    table->slow_count = 0;
    table->max_length = 0;
    
    for (int i = 0; i < count; i++) {
        if (lengths[i] > 0 && lengths[i] <= 15) {
            bl_count[lengths[i]]++;
            if (lengths[i] > max_len) max_len = lengths[i];
        }
    }
    table->max_length = max_len;
    if (max_len == 0) return 0;
    
    int code = 0;
    for (int bits = 1; bits <= 15; bits++) {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }
    
    for (int sym = 0; sym < count; sym++) {
        int len = lengths[sym];
        if (len == 0) continue;
        
        int c = next_code[len]++;
        uint32_t rev = im_huff_bit_reverse(c, len);
        
        if (len <= HUFF_FAST_BITS) {
            uint16_t entry = (uint16_t)(sym | (len << HUFF_LEN_SHIFT));
            int fill = 1 << (HUFF_FAST_BITS - len);
            for (int j = 0; j < fill; j++) {
                table->fast[rev | (j << len)] = entry;
            }
        } else {
            table->fast[rev & (HUFF_FAST_SIZE - 1)] = HUFF_SLOW_FLAG;
            if (table->slow_count < 320) {
                int si = table->slow_count++;
                table->slow_sym[si] = sym;
                table->slow_len[si] = len;
                table->slow_code[si] = rev;
            }
        }
    }
    
    return 0;
}

/*
 * Decode one symbol from the bitstream using the Huffman table.
 * Returns the symbol value (0-285 for lit/len, 0-31 for dist) or -1 on error.
 */

/* Fixed literal/length table (symbols 0-285) */
static const uint16_t im_fixed_lit_table[512] = {
    0x1D00,0x2050,0x2010,0x2118,0x1D10,0x2070,0x2030,0x24C0,0x1D08,0x2060,0x2020,0x24A0,0x2000,0x2080,0x2040,0x24E0,
    0x1D04,0x2058,0x2018,0x2490,0x1D14,0x2078,0x2038,0x24D0,0x1D0C,0x2068,0x2028,0x24B0,0x2008,0x2088,0x2048,0x24F0,
    0x1D02,0x2054,0x2014,0x211C,0x1D12,0x2074,0x2034,0x24C8,0x1D0A,0x2064,0x2024,0x24A8,0x2004,0x2084,0x2044,0x24E8,
    0x1D06,0x205C,0x201C,0x2498,0x1D16,0x207C,0x203C,0x24D8,0x1D0E,0x206C,0x202C,0x24B8,0x200C,0x208C,0x204C,0x24F8,
    0x1D01,0x2052,0x2012,0x211A,0x1D11,0x2072,0x2032,0x24C4,0x1D09,0x2062,0x2022,0x24A4,0x2002,0x2082,0x2042,0x24E4,
    0x1D05,0x205A,0x201A,0x2494,0x1D15,0x207A,0x203A,0x24D4,0x1D0D,0x206A,0x202A,0x24B4,0x200A,0x208A,0x204A,0x24F4,
    0x1D03,0x2056,0x2016,0x211E,0x1D13,0x2076,0x2036,0x24CC,0x1D0B,0x2066,0x2026,0x24AC,0x2006,0x2086,0x2046,0x24EC,
    0x1D07,0x205E,0x201E,0x249C,0x1D17,0x207E,0x203E,0x24DC,0x1D0F,0x206E,0x202E,0x24BC,0x200E,0x208E,0x204E,0x24FC,
    0x1D00,0x2051,0x2011,0x2119,0x1D10,0x2071,0x2031,0x24C2,0x1D08,0x2061,0x2021,0x24A2,0x2001,0x2081,0x2041,0x24E2,
    0x1D04,0x2059,0x2019,0x2492,0x1D14,0x2079,0x2039,0x24D2,0x1D0C,0x2069,0x2029,0x24B2,0x2009,0x2089,0x2049,0x24F2,
    0x1D02,0x2055,0x2015,0x211D,0x1D12,0x2075,0x2035,0x24CA,0x1D0A,0x2065,0x2025,0x24AA,0x2005,0x2085,0x2045,0x24EA,
    0x1D06,0x205D,0x201D,0x249A,0x1D16,0x207D,0x203D,0x24DA,0x1D0E,0x206D,0x202D,0x24BA,0x200D,0x208D,0x204D,0x24FA,
    0x1D01,0x2053,0x2013,0x211B,0x1D11,0x2073,0x2033,0x24C6,0x1D09,0x2063,0x2023,0x24A6,0x2003,0x2083,0x2043,0x24E6,
    0x1D05,0x205B,0x201B,0x2496,0x1D15,0x207B,0x203B,0x24D6,0x1D0D,0x206B,0x202B,0x24B6,0x200B,0x208B,0x204B,0x24F6,
    0x1D03,0x2057,0x2017,0x211F,0x1D13,0x2077,0x2037,0x24CE,0x1D0B,0x2067,0x2027,0x24AE,0x2007,0x2087,0x2047,0x24EE,
    0x1D07,0x205F,0x201F,0x249E,0x1D17,0x207F,0x203F,0x24DE,0x1D0F,0x206F,0x202F,0x24BE,0x200F,0x208F,0x204F,0x24FE,
    0x1D00,0x2050,0x2010,0x2118,0x1D10,0x2070,0x2030,0x24C1,0x1D08,0x2060,0x2020,0x24A1,0x2000,0x2080,0x2040,0x24E1,
    0x1D04,0x2058,0x2018,0x2491,0x1D14,0x2078,0x2038,0x24D1,0x1D0C,0x2068,0x2028,0x24B1,0x2008,0x2088,0x2048,0x24F1,
    0x1D02,0x2054,0x2014,0x211C,0x1D12,0x2074,0x2034,0x24C9,0x1D0A,0x2064,0x2024,0x24A9,0x2004,0x2084,0x2044,0x24E9,
    0x1D06,0x205C,0x201C,0x2499,0x1D16,0x207C,0x203C,0x24D9,0x1D0E,0x206C,0x202C,0x24B9,0x200C,0x208C,0x204C,0x24F9,
    0x1D01,0x2052,0x2012,0x211A,0x1D11,0x2072,0x2032,0x24C5,0x1D09,0x2062,0x2022,0x24A5,0x2002,0x2082,0x2042,0x24E5,
    0x1D05,0x205A,0x201A,0x2495,0x1D15,0x207A,0x203A,0x24D5,0x1D0D,0x206A,0x202A,0x24B5,0x200A,0x208A,0x204A,0x24F5,
    0x1D03,0x2056,0x2016,0x211E,0x1D13,0x2076,0x2036,0x24CD,0x1D0B,0x2066,0x2026,0x24AD,0x2006,0x2086,0x2046,0x24ED,
    0x1D07,0x205E,0x201E,0x249D,0x1D17,0x207E,0x203E,0x24DD,0x1D0F,0x206E,0x202E,0x24BD,0x200E,0x208E,0x204E,0x24FD,
    0x1D00,0x2051,0x2011,0x2119,0x1D10,0x2071,0x2031,0x24C3,0x1D08,0x2061,0x2021,0x24A3,0x2001,0x2081,0x2041,0x24E3,
    0x1D04,0x2059,0x2019,0x2493,0x1D14,0x2079,0x2039,0x24D3,0x1D0C,0x2069,0x2029,0x24B3,0x2009,0x2089,0x2049,0x24F3,
    0x1D02,0x2055,0x2015,0x211D,0x1D12,0x2075,0x2035,0x24CB,0x1D0A,0x2065,0x2025,0x24AB,0x2005,0x2085,0x2045,0x24EB,
    0x1D06,0x205D,0x201D,0x249B,0x1D16,0x207D,0x203D,0x24DB,0x1D0E,0x206D,0x202D,0x24BB,0x200D,0x208D,0x204D,0x24FB,
    0x1D01,0x2053,0x2013,0x211B,0x1D11,0x2073,0x2033,0x24C7,0x1D09,0x2063,0x2023,0x24A7,0x2003,0x2083,0x2043,0x24E7,
    0x1D05,0x205B,0x201B,0x2497,0x1D15,0x207B,0x203B,0x24D7,0x1D0D,0x206B,0x202B,0x24B7,0x200B,0x208B,0x204B,0x24F7,
    0x1D03,0x2057,0x2017,0x211F,0x1D13,0x2077,0x2037,0x24CF,0x1D0B,0x2067,0x2027,0x24AF,0x2007,0x2087,0x2047,0x24EF,
    0x1D07,0x205F,0x201F,0x249F,0x1D17,0x207F,0x203F,0x24DF,0x1D0F,0x206F,0x202F,0x24BF,0x200F,0x208F,0x204F,0x24FF
};

/* Fixed distance table (symbols 0-31, all 5-bit codes) */
static const uint16_t im_fixed_dist_table[512] = {
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F,
    0x1400,0x1410,0x1408,0x1418,0x1404,0x1414,0x140C,0x141C,0x1402,0x1412,0x140A,0x141A,0x1406,0x1416,0x140E,0x141E,
    0x1401,0x1411,0x1409,0x1419,0x1405,0x1415,0x140D,0x141D,0x1403,0x1413,0x140B,0x141B,0x1407,0x1417,0x140F,0x141F
};
static const uint16_t im_length_base[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};

/* Extra bits to read for each length code */
static const uint8_t im_length_extra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};

/* Distance codes 0-29 map to these base distances */
static const uint16_t im_distance_base[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577
};

/* Extra bits to read for each distance code */
static const uint8_t im_distance_extra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

static const uint8_t im_fixed_literal_lengths[288] = {
    /* 0-143: length 8 */
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    /* 144-255: length 9 */
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    /* 256-279: length 7 */
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    /* 280-287: length 8 */
    8,8,8,8,8,8,8,8
};

static const uint8_t im_fixed_distance_lengths[32] = {
    5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5
};

static void im_png_unfilter(im_png_info *info) {
    size_t bpp = (info->bits_per_channel * info->channel_count + 7) / 8;
    size_t rowbytes = (info->width * info->channel_count * info->bits_per_channel + 7) / 8;
    size_t stride = rowbytes + 1;
    
    uint8_t *data = (uint8_t*)info->png_pixels;
    
    /* Zero row for first scanline's "previous" */
    uint8_t *zero_row = (uint8_t*)calloc(1, rowbytes);
    if (!zero_row) return;
    
    for (size_t y = 0; y < info->height; y++) {
        uint8_t filter = data[y * stride];
        uint8_t *row = data + y * stride + 1;
        const uint8_t *prev = (y > 0) ? (data + (y - 1) * stride + 1) : zero_row;
        
        switch (filter) {
            case 0: break;
            case 1: im_unfilter_sub(row, rowbytes, bpp); break;
            case 2: im_unfilter_up(row, prev, rowbytes); break;
            case 3: im_unfilter_avg(row, prev, rowbytes, bpp); break;
            case 4: im_unfilter_paeth(row, prev, rowbytes, bpp); break;
        }
    }
    
    free(zero_row);
    
    /* Compact: remove filter bytes */
    uint8_t *compacted = (uint8_t*)malloc(info->height * rowbytes);
    if (compacted) {
        for (size_t y = 0; y < info->height; y++) {
            memcpy(compacted + y * rowbytes, data + y * stride + 1, rowbytes);
        }
        free(info->png_pixels);
        info->png_pixels = compacted;
    }
}

// Length codes 257-285 map to these base lengths
static const uint16_t length_base[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};

// Extra bits to read for each length code
static const uint8_t length_extra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};

// Distance codes 0-29 map to these base distances
static const uint16_t distance_base[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577
};
// Extra bits to read for each distance code
static const uint8_t distance_extra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

/* Decode from static fixed table - inline for speed */
#define DECODE_FIXED(bs, table, sym, len) do { \
    uint32_t _peek = (bs)->bits & (HUFF_FAST_SIZE - 1); \
    uint16_t _entry = (table)[_peek]; \
    (len) = (_entry >> HUFF_LEN_SHIFT) & HUFF_LEN_MASK; \
    (sym) = _entry & HUFF_SYM_MASK; \
} while(0)

/* Decode from dynamic table with slow path */
static int huff_decode_dynamic(im_bitstream *bs, im_huffman_table *table) {
    uint32_t peek = bs->bits & (HUFF_FAST_SIZE - 1);
    uint16_t entry = table->fast[peek];
    
    if (entry != 0 && !(entry & HUFF_SLOW_FLAG)) {
        int len = (entry >> HUFF_LEN_SHIFT) & HUFF_LEN_MASK;
        im_bs_drop(bs, len);
        return entry & HUFF_SYM_MASK;
    }
    
    /* Slow path for long codes */
    for (int len = HUFF_FAST_BITS + 1; len <= table->max_length; len++) {
        if (bs->count < len) im_bs_refil(bs);
        uint32_t code = bs->bits & ((1u << len) - 1);
        
        for (int i = 0; i < table->slow_count; i++) {
            if (table->slow_len[i] == len && table->slow_code[i] == code) {
                im_bs_drop(bs, len);
                return table->slow_sym[i];
            }
        }
    }
    
    return -1;
}

static int64_t im_inflate(const uint8_t *compressed, size_t comp_size, uint8_t *output, size_t output_size) {
    im_bitstream bs;
    im_bs_init(&bs, compressed, comp_size);
    
    size_t out_pos = 0;
    int bfinal;
    
    do {
        bfinal = im_bs_read(&bs, 1);
        int btype = im_bs_read(&bs, 2);
        
        if (btype == 0) {
            /* Uncompressed block */
            im_bs_align(&bs);
            uint16_t len = im_bs_read(&bs, 16);
            uint16_t nlen = im_bs_read(&bs, 16);
            
            if ((len ^ nlen) != 0xFFFF) return -1;
            
            for (uint16_t i = 0; i < len; i++) {
                if (out_pos >= output_size) return -1;
                output[out_pos++] = im_bs_read(&bs, 8);
            }
            
        } else if (btype == 1) {
            /*
             * Fixed Huffman with TWO-SYMBOL-AT-A-TIME optimization
             */
            while (1) {
                im_bs_refil(&bs);
                
                int sym1, len1;
                DECODE_FIXED(&bs, im_fixed_lit_table, sym1, len1);
                im_bs_drop(&bs, len1);
                
                if (sym1 < 256) {
                    /* First symbol is literal - try to decode second */
                    int sym2, len2;
                    DECODE_FIXED(&bs, im_fixed_lit_table, sym2, len2);
                    
                    if (sym2 < 256) {
                        /* Both are literals - write both! */
                        if (out_pos + 2 > output_size) return -1;
                        output[out_pos++] = (uint8_t)sym1;
                        output[out_pos++] = (uint8_t)sym2;
                        im_bs_drop(&bs, len2);
                        continue;
                    }
                    
                    /* Second is not a literal - write first, process second */
                    if (out_pos >= output_size) return -1;
                    output[out_pos++] = (uint8_t)sym1;
                    im_bs_drop(&bs, len2);
                    sym1 = sym2;
                } 
                
                if (sym1 == 256) {
                    break;  /* End of block */
                }
                
                /* Length code 257-285 */
                int len_idx = sym1 - 257;
                if (len_idx < 0 || len_idx >= 29) return -1;
                
                int length = im_length_base[len_idx];
                if (im_length_extra[len_idx] > 0) {
                    length += im_bs_read(&bs, im_length_extra[len_idx]);
                }
                
                /* Decode distance */
                im_bs_refil(&bs);
                int dist_sym, dist_len;
                DECODE_FIXED(&bs, im_fixed_dist_table, dist_sym, dist_len);
                im_bs_drop(&bs, dist_len);
                
                if (dist_sym >= 30) return -1;
                
                int distance = im_distance_base[dist_sym];
                if (im_distance_extra[dist_sym] > 0) {
                    distance += im_bs_read(&bs, im_distance_extra[dist_sym]);
                }
                
                if ((size_t)distance > out_pos) return -1;
                if (out_pos + length > output_size) return -1;
                
                /* Copy from back-reference */
                uint8_t *src = output + out_pos - distance;
                uint8_t *dst = output + out_pos;
                for (int j = 0; j < length; j++) {
                    *dst++ = *src++;
                }
                out_pos += length;
            }
            
        } else if (btype == 2) {
            /* Dynamic Huffman - also with two-symbol optimization */
            int hlit = im_bs_read(&bs, 5) + 257;
            int hdist = im_bs_read(&bs, 5) + 1;
            int hclen = im_bs_read(&bs, 4) + 4;
            
            static const int cl_order[19] = {
                16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
            };
            
            uint8_t cl_lengths[19] = {0};
            for (int i = 0; i < hclen; i++) {
                cl_lengths[cl_order[i]] = im_bs_read(&bs, 3);
            }
            
            im_huffman_table cl_table = {0};
            im_build_huffman_table(&cl_table, cl_lengths, 19);
            
            uint8_t lengths[288 + 32] = {0};
            int i = 0;
            int total = hlit + hdist;
            
            while (i < total) {
                im_bs_refil(&bs);
                int sym = huff_decode_dynamic(&bs, &cl_table);
                if (sym < 0) return -1;
                
                if (sym < 16) {
                    lengths[i++] = sym;
                } else if (sym == 16) {
                    int repeat = im_bs_read(&bs, 2) + 3;
                    uint8_t prev = (i > 0) ? lengths[i - 1] : 0;
                    while (repeat-- > 0 && i < total) lengths[i++] = prev;
                } else if (sym == 17) {
                    int repeat = im_bs_read(&bs, 3) + 3;
                    while (repeat-- > 0 && i < total) lengths[i++] = 0;
                } else if (sym == 18) {
                    int repeat = im_bs_read(&bs, 7) + 11;
                    while (repeat-- > 0 && i < total) lengths[i++] = 0;
                }
            }
            
            im_huffman_table dyn_lit = {0};
            im_huffman_table dyn_dist = {0};
            im_build_huffman_table(&dyn_lit, lengths, hlit);
            im_build_huffman_table(&dyn_dist, lengths + hlit, hdist);
            
            /* Main decode loop with two-symbol optimization */
            while (1) {
                im_bs_refil(&bs);
                
                int sym1 = huff_decode_dynamic(&bs, &dyn_lit);
                if (sym1 < 0) return -1;
                
                if (sym1 < 256) {
                    /* First is literal - try second */
                    int sym2 = huff_decode_dynamic(&bs, &dyn_lit);
                    if (sym2 < 0) return -1;
                    
                    if (sym2 < 256) {
                        /* Both literals */
                        if (out_pos + 2 > output_size) return -1;
                        output[out_pos++] = (uint8_t)sym1;
                        output[out_pos++] = (uint8_t)sym2;
                        continue;
                    }
                    
                    /* Write first, handle second */
                    if (out_pos >= output_size) return -1;
                    output[out_pos++] = (uint8_t)sym1;
                    sym1 = sym2;
                }
                
                if (sym1 == 256) break;
                
                int len_idx = sym1 - 257;
                if (len_idx < 0 || len_idx >= 29) return -1;
                
                int length = im_length_base[len_idx];
                if (im_length_extra[len_idx] > 0) {
                    length += im_bs_read(&bs, im_length_extra[len_idx]);
                }
                
                im_bs_refil(&bs);
                int dist_sym = huff_decode_dynamic(&bs, &dyn_dist);
                if (dist_sym < 0 || dist_sym >= 30) return -1;
                
                int distance = im_distance_base[dist_sym];
                if (im_distance_extra[dist_sym] > 0) {
                    distance += im_bs_read(&bs, im_distance_extra[dist_sym]);
                }
                
                if ((size_t)distance > out_pos) return -1;
                if (out_pos + length > output_size) return -1;
                
                uint8_t *src = output + out_pos - distance;
                uint8_t *dst = output + out_pos;
                for (int j = 0; j < length; j++) {
                    *dst++ = *src++;
                }
                out_pos += length;
            }
            
        } else {
            return -1;  /* Invalid block type 3 */
        }
        
    } while (!bfinal);
    
    return (int64_t)out_pos;
}

unsigned char *im_png_decompress(im_png_info *info, unsigned char *current_IDAT_chunk, int *idat_chunk_count) {
    uint32_t comp_data_size = 0;
    uint32_t tmp = 0;
    unsigned char *start = current_IDAT_chunk;

    /* Find the total size of the compressed data */
    while (*(uint32_t*)(current_IDAT_chunk + PNG_CHUNK_DATA_LEN) == CHUNK_IDAT) {
        im_memcpy(&tmp, current_IDAT_chunk, PNG_CHUNK_DATA_LEN);
        endian_swap(&tmp);
        comp_data_size += tmp;
        current_IDAT_chunk = im_png_peek_next_chunk(info, current_IDAT_chunk);
        (*idat_chunk_count)++;
    }

    /* Allocate and concatenate IDAT data */
    unsigned char *compressed_data = (unsigned char*)malloc(comp_data_size);
    if (!compressed_data) return NULL;

    size_t offset = 0;
    uint32_t current_chunk_data_len = 0;
    current_IDAT_chunk = start;
    
    while (*(uint32_t*)(current_IDAT_chunk + 4) == CHUNK_IDAT) {
        im_memcpy(&current_chunk_data_len, current_IDAT_chunk, PNG_CHUNK_DATA_LEN);
        endian_swap(&current_chunk_data_len);
        im_memcpy(compressed_data + offset, 
                  current_IDAT_chunk + PNG_CHUNK_DATA_LEN + PNG_CHUNK_TYPE_LEN, 
                  current_chunk_data_len);
        offset += current_chunk_data_len;
        current_IDAT_chunk += PNG_CHUNK_DATA_LEN + PNG_CHUNK_TYPE_LEN + 
                              current_chunk_data_len + PNG_CHUNK_CRC_LEN;
    }

    /* Parse zlib header */
    uint8_t cmf = compressed_data[0];
    uint8_t flg = compressed_data[1];
    
    if (((cmf << 8) + flg) % 31 != 0) {
        free(compressed_data);
        IM_ERR( "Error: zlib integrity check failed.");
        return NULL;
    }
    
    uint8_t comp_method = cmf & 0x0F;
    if (comp_method != 8) {
        free(compressed_data);
        IM_ERR("Error: unsupported compression method %d", comp_method);
        return NULL;
    }

    /* Calculate output size */
    size_t bytes_per_scanline = (info->width * info->channel_count * info->bits_per_channel + 7) / 8;
    size_t output_size = info->height * (bytes_per_scanline + 1);  /* +1 for filter byte */
    
    info->png_pixels = malloc(output_size);
    if (!info->png_pixels) {
        free(compressed_data);
        return NULL;
    }

    /* Decompress (skip 2-byte zlib header) */
    int64_t result = im_inflate(compressed_data + 2, comp_data_size - 2,
                                info->png_pixels, output_size);
    
    free(compressed_data);
    
    if (result < 0) {
        free(info->png_pixels);
        info->png_pixels = NULL;
        return NULL;
    }

    /* Unfilter the image data */
    im_png_unfilter(info);
    
    return info->png_pixels;
}

unsigned char *im_png_load(unsigned char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {

    im_png_info info = {0};
    info.first_ihdr = im_true;
    info.png_file = image_file;
    info.at = image_file;

    info.end_of_file = image_file + file_size;
    unsigned char *png_sig = (unsigned char*)consume(&info.at, info.end_of_file, sizeof(png_sig));

#ifdef IM_DEBUG
    im_print_bytes(png_sig, PNG_SIG_LEN);
#endif

    unsigned char *next_chunk_type = NULL;
    next_chunk_type = get_next_chunk_type(&info);
    if(!next_chunk_type) return NULL;

    while(*(uint32_t*)next_chunk_type != CHUNK_IEND) {
        next_chunk_type = get_next_chunk_type(&info);
        if(!next_chunk_type) return NULL;
        IM_INFO("chunk: %.*s", 4, next_chunk_type);
        switch(*(uint32_t*)next_chunk_type)  {
            case CHUNK_IHDR:
                im_png_parse_chunk_IHDR(&info);
                *width = info.width;
                *height = info.height;
                *num_channels = info.channel_count;
                IM_INFO("-----------------------------");
                break;
            case CHUNK_cHRM:
                im_png_parse_chunk_cHRM(&info);
                IM_INFO("-----------------------------");
                break;
            case CHUNK_iCCP:
                skip_chunk(&info);
                break;
            case CHUNK_sBIT:
                skip_chunk(&info);
                break;
            case CHUNK_sRGB:
                skip_chunk(&info);
                break;
            case CHUNK_PLTE:
				im_png_parse_chunk_PLTE(&info);
                break;
            case CHUNK_bKGD:
                im_png_parse_chunk_bKGD(&info);
                IM_INFO("-----------------------------");
                break;
            case CHUNK_hIST:
                skip_chunk(&info);
                break;
            case CHUNK_tRNS:
                skip_chunk(&info);
                break;
            case CHUNK_pHYs:
                skip_chunk(&info);
                break;
            case CHUNK_sPLT:
                skip_chunk(&info);
                break;
            case CHUNK_IDAT: {
                int idat_chunk_count = 0;
                unsigned char *err = im_png_decompress(&info, next_chunk_type - PNG_CHUNK_DATA_LEN, &idat_chunk_count);
                if(!err) return NULL;
                for(int i = 0; i < idat_chunk_count; i++) {
                    skip_chunk(&info);
                }
                IM_INFO("-----------------------------");
                break;
            }
            case CHUNK_iTXt:
                skip_chunk(&info);
                break;
            case CHUNK_tEXt:
                im_png_parse_chunk_tEXt(&info);
                IM_INFO("-----------------------------");
                break;
            case CHUNK_zTXt:
                skip_chunk(&info);
                break;
            case CHUNK_tIME:
                im_png_parse_chunk_tIME(&info);
                IM_INFO("-----------------------------");
                break;
            case CHUNK_gAMA:
                im_png_parse_chunk_gAMA(&info);
                IM_INFO("-----------------------------");
                break;
            case CHUNK_IEND:
                im_png_parse_chunk_IEND(&info);
                IM_INFO("-----------------------------");
                break;
            default:
                skip_chunk(&info);
                break;
        }
    }

    if (info.color_type == PALETTE && info.png_pixels != NULL) {
        unsigned char *rgb_pixels = im_png_expand_palette(&info);
        if (rgb_pixels) {
            free(info.png_pixels);
            info.png_pixels = rgb_pixels;
            *num_channels = 3;  /* Palette images expand to RGB */
        } else {
            free(info.png_pixels);
            return NULL;
        }
    }
    
    return info.png_pixels;
}

static unsigned char consume_byte(unsigned char **at, unsigned char *end_of_file) {
    unsigned char *orig = *at;
    if(*at < end_of_file) {
        *at += 1;
        return *orig;
    }
    IM_ERR("Error: %s(), will not read past end of file.", __func__);
    return 0;  // Return 0 on error, which will stop the while loop
}

/* peeks the current byte without consuming it */
static unsigned char peek_byte(unsigned char *at, unsigned char *end_of_file) {
    if (at < end_of_file) {
        return *at;
    }
    IM_ERR("Error: %s(), will not peek past end of file.", __func__);
    return *at;
}

im_bool is_end_of_line(unsigned char ch) {
    return ch == '\n' || ch == '\r';
}

unsigned char *im_parse_pnm_ascii_header(unsigned char *at, unsigned char *end_of_file, int *width, int *height) {

    /* skip sig */
    consume(&at, end_of_file, 2);

    /* eat whitespaces after sig */
    unsigned char c = 0;
    while ((c = peek_byte(at, end_of_file)) && (c == ' ' || c == '\n' || c == '\r' || c == '\t')) {
        consume_byte(&at, end_of_file);
    }

    /* eat comments after whitespaces*/

    while(*at == '#') {
        if(peek_byte(at, end_of_file) == '#') {
            unsigned char byte = 0;
            do{
                byte = consume_byte(&at, end_of_file);
            }while(!is_end_of_line(byte));
        }
    }

    /* Get width */
    c = peek_byte(at, end_of_file);
    if (c >= '0' && c <= '9') {
        int value = 0;
        while ((c = peek_byte(at, end_of_file)) >= '0' && c <= '9') {
            value = value * 10 + (c - '0');
            consume_byte(&at, end_of_file);
        }
        *width = value;
    } else {
        IM_ERR("Could not get the width of the image because the width is not\nwhere we expected it to be in the file. Malformed image. Not going to load.");
        return NULL;
    }

    /* skip whitespace characters between width and height */
    while ((c = peek_byte(at, end_of_file)) && (c == ' ' || c == '\t')) {
        consume_byte(&at, end_of_file);
    }

    /* Get height */
    c = peek_byte(at, end_of_file);
    if (c >= '0' && c <= '9') {
        int value = 0;
        while ((c = peek_byte(at, end_of_file)) >= '0' && c <= '9') {
            value = value * 10 + (c - '0');
            consume_byte(&at, end_of_file);
        }
        *height = value;
    } else {
        IM_ERR("Could not get the height of the image because the height is not\nwhere we expected it to be in the file. Malformed image. Not going to load.");
        return NULL;
    }

    /* width and height sanity checks */
    if (*width <= 0 ) {
        IM_ERR("The width of the image is less than or equal to 0.\n Not going to load the image.");
        return NULL;
    }

    if(*height <= 0) {
        IM_ERR("The height of the image is less than or equal to 0.\n Not going to load the image.");
        return NULL;
    }

    if(*width > 100000) {
        IM_ERR("The width of the image is a stupidly large number (bigger than 100,000).\n Not going to load the image.");
        return NULL;
    }

    if (*height > 100000) {
        IM_ERR("The height of the image is a stupidly large number (bigger than 100,000).\n Not going to load the image.");
        return NULL;
    }

    /* skip whitespaces and new line characters after width and height */
    while ((c = peek_byte(at, end_of_file)) && (c == ' ' || c == '\n' || c == '\r' || c == '\t')) {
        consume_byte(&at, end_of_file);
    }
    return at;
}

unsigned char *im_p1_load(unsigned char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    unsigned char *at = image_file;
    unsigned char *end_of_file = image_file + file_size;
    unsigned char *pixels = NULL;
    unsigned char *pixel_write_pos = NULL;
    size_t pixels_written = 0;
    *num_channels = 1;
    *width = 0;
    *height = 0;

    at = im_parse_pnm_ascii_header(at, end_of_file, width, height);
    if (!at) return NULL;

    size_t pixel_count = (size_t)(*width) * (*height);
    pixels = malloc(pixel_count);
    if (!pixels) return NULL;
    pixel_write_pos = pixels;
    pixels_written = 0;
    unsigned char c = 0;

    while((c = consume_byte(&at, end_of_file)) && pixels_written < pixel_count) {
        if (c == '0') {
            *pixel_write_pos++ = 0;    /* white */
            pixels_written++;
        }
        else if (c == '1') {
            *pixel_write_pos++ = 255;  /* black */
            pixels_written++;
        }
        /* else skip whitespace and other characters */
    }
    return pixels;
}

int get_max_val(unsigned char **at, unsigned char *end_of_file) {
    int max_val = 0;
    unsigned char c = peek_byte(*at, end_of_file);

    if (c >= '0' && c <= '9') {
        while ((c = peek_byte(*at, end_of_file)) >= '0' && c <= '9') {
            max_val = max_val * 10 + (c - '0');
            consume_byte(at, end_of_file);
        }
        return max_val;
    }

    return -1; // Error: no valid number found
}

unsigned char *im_p2_load(unsigned char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    unsigned char *at = image_file;
    unsigned char *end_of_file = image_file + file_size;
    unsigned char *pixels = NULL;
    *num_channels = 1;
    *width = 0;
    *height = 0;

    at = im_parse_pnm_ascii_header(at, end_of_file, width, height);
    if (!at) return NULL;

    int max_val = get_max_val(&at, end_of_file);
    if (max_val <= 0) return NULL;

    float multiplication_factor = 255.0f / (float)max_val;

    /* skip white space after the max val */
    unsigned char c;
    while ((c = peek_byte(at, end_of_file)) && (c == ' ' || c == '\n' || c == '\r' || c == '\t')) {
        consume_byte(&at, end_of_file);
    }

    size_t pixel_count = (size_t)(*width) * (*height);
    pixels = malloc(pixel_count);
    if (!pixels) return NULL;

    for (size_t i = 0; i < pixel_count; i++) {
        while ((c = peek_byte(at, end_of_file)) &&
              (c == ' ' || c == '\n' || c == '\r' || c == '\t')) {
            consume_byte(&at, end_of_file);
        }

        int value = 0;
        c = peek_byte(at, end_of_file);
        if (c < '0' || c > '9') return NULL;

        while ((c = peek_byte(at, end_of_file)) >= '0' && c <= '9') {
            value = value * 10 + (c - '0');
            consume_byte(&at, end_of_file);
        }

        value = (int)(value * multiplication_factor);
        pixels[i] = (unsigned char)value;
    }
    return pixels;
}

unsigned char *im_p3_load(unsigned char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    unsigned char *at = image_file;
    unsigned char *end_of_file = image_file + file_size;
    unsigned char *pixels = NULL;
    *num_channels = 3;
    *width = 0;
    *height = 0;

    at = im_parse_pnm_ascii_header(at, end_of_file, width, height);
    if (!at) return NULL;

    int max_val = get_max_val(&at, end_of_file);
    if (max_val <= 0) return NULL;

    float multiplication_factor = 255.0f / (float)max_val;

    /* skip white space after the max val */
    unsigned char c;
    while ((c = peek_byte(at, end_of_file)) && (c == ' ' || c == '\n' || c == '\r' || c == '\t')) {
        consume_byte(&at, end_of_file);
    }

    size_t pixel_count = (size_t)(*width) * (*height);
    pixels = malloc(pixel_count * 3);
    if (!pixels) return NULL;

    for (size_t i = 0; i < pixel_count; i++) {
        for(size_t j = 0; j < 3; j++) {
            while ((c = peek_byte(at, end_of_file)) &&
                  (c == ' ' || c == '\n' || c == '\r' || c == '\t')) {
                consume_byte(&at, end_of_file);
            }

            int value = 0;
            c = peek_byte(at, end_of_file);
            if (c < '0' || c > '9') return NULL;

            while ((c = peek_byte(at, end_of_file)) >= '0' && c <= '9') {
                value = value * 10 + (c - '0');
                consume_byte(&at, end_of_file);
            }

            value = (int)(value * multiplication_factor);
            pixels[i*3 + j] = (unsigned char)value;
        }
    }
    return pixels;
}

unsigned char *im_p4_load(unsigned char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    unsigned char *at = image_file;
    unsigned char *end_of_file = image_file + file_size;
    unsigned char *pixels = NULL;
    *num_channels = 1;
    *width = 0;
    *height = 0;

    at = im_parse_pnm_ascii_header(at, end_of_file, width, height);
    if (!at) return NULL;

    size_t pixel_count = (size_t)(*width) * (*height);
    pixels = malloc(pixel_count);
    if (!pixels) return NULL;

    /* P4 stores pixels as packed bits: 1 bit per pixel */
    size_t bytes_per_row = (*width + 7) / 8;  /* Round up to nearest byte */
    size_t pixel_idx = 0;

    for (int y = 0; y < *height; y++) {
        for (size_t byte_idx = 0; byte_idx < bytes_per_row && pixel_idx < pixel_count; byte_idx++) {
            unsigned char byte = consume_byte(&at, end_of_file);

            /* Extract bits from MSB to LSB */
            for (int bit = 7; bit >= 0 && pixel_idx < pixel_count; bit--) {
                int bit_value = (byte >> bit) & 1;
                /* 0 = white (255), 1 = black (0) */
                pixels[pixel_idx++] = bit_value ? 0 : 255;
            }
        }
    }

    return pixels;
}

unsigned char *im_p5_load(unsigned char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    unsigned char *at = image_file;
    unsigned char *end_of_file = image_file + file_size;
    unsigned char *pixels = NULL;
    *num_channels = 1;
    *width = 0;
    *height = 0;

    at = im_parse_pnm_ascii_header(at, end_of_file, width, height);
    if (!at) return NULL;

    int max_val = get_max_val(&at, end_of_file);
    if (max_val <= 0) return NULL;

    float multiplication_factor = 255.0f / (float)max_val;

    /* skip single whitespace character after max val (usually newline) */
    unsigned char c = peek_byte(at, end_of_file);
    if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
        consume_byte(&at, end_of_file);
    }

    size_t pixel_count = (size_t)(*width) * (*height);
    pixels = malloc(pixel_count);
    if (!pixels) return NULL;

    /* P5 stores raw binary data: 1 byte per pixel */
    if (max_val < 256) {
        /* 8-bit grayscale */
        for (size_t i = 0; i < pixel_count; i++) {
            unsigned char value = consume_byte(&at, end_of_file);
            pixels[i] = (unsigned char)(value * multiplication_factor);
        }
    } else {
        /* 16-bit grayscale (big-endian) - read MSB first */
        for (size_t i = 0; i < pixel_count; i++) {
            unsigned char msb = consume_byte(&at, end_of_file);
            unsigned char lsb = consume_byte(&at, end_of_file);
            int value = (msb << 8) | lsb;
            pixels[i] = (unsigned char)(value * multiplication_factor);
        }
    }

    return pixels;
}

unsigned char *im_p6_load(unsigned char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    unsigned char *at = image_file;
    unsigned char *end_of_file = image_file + file_size;
    unsigned char *pixels = NULL;
    *num_channels = 3;
    *width = 0;
    *height = 0;

    at = im_parse_pnm_ascii_header(at, end_of_file, width, height);
    if (!at) return NULL;

    int max_val = get_max_val(&at, end_of_file);
    if (max_val <= 0) return NULL;

    float multiplication_factor = 255.0f / (float)max_val;

    /* skip single whitespace character after max val (usually newline) */
    unsigned char c = peek_byte(at, end_of_file);
    if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
        consume_byte(&at, end_of_file);
    }

    size_t pixel_count = (size_t)(*width) * (*height);
    pixels = malloc(pixel_count * 3);
    if (!pixels) return NULL;

    /* P6 stores raw binary RGB data: 3 bytes per pixel (or 6 if 16-bit) */
    if (max_val < 256) {
        /* 8-bit RGB */
        for (size_t i = 0; i < pixel_count * 3; i++) {
            unsigned char value = consume_byte(&at, end_of_file);
            pixels[i] = (unsigned char)(value * multiplication_factor);
        }
    } else {
        /* 16-bit RGB (big-endian) */
        for (size_t i = 0; i < pixel_count * 3; i++) {
            unsigned char msb = consume_byte(&at, end_of_file);
            unsigned char lsb = consume_byte(&at, end_of_file);
            int value = (msb << 8) | lsb;
            pixels[i] = (unsigned char)(value * multiplication_factor);
        }
    }

    return pixels;
}

typedef struct color_coords {
  int32_t x;
  int32_t y;
  int32_t z;
} color_coords;

typedef struct px_clr_crds {
    color_coords red;
    color_coords green;
    color_coords blue;
} px_clr_crds;

typedef struct rgb_quad {
  uint8_t blue;
  uint8_t green;
  uint8_t red;
  uint8_t reserved;
} rgb_quad;

enum {
    BMP_COMP_RGB = 0x0000,
    BMP_COMP_RLE8 = 0x0001,
    BMP_COMP_RLE4 = 0x0002,
    BMP_COMP_BITFIELDS = 0x0003,
    BMP_COMP_JPEG = 0x0004,
    BMP_COMP_PNG = 0x0005,
    BMP_COMP_CMYK = 0x000B,
    BMP_COMP_CMYKRLE8 = 0x000C,
    BMP_COMP_CMYKRLE4 = 0x000D
}im_bmp_compression;

enum {
    BMP_CLRSPACE_GAMMA_AND_ENDPOINTS_PROVIDED = 0x00000000,
    BMP_CLRSPACE_SRGB = 0x73524742,
    BMP_CLRSPACE_WINDOWS = 0x57696E20
}im_bmp_logical_color_space;

enum {
    BMP_CLRSPACE_IN_OTHER_FILE = 0x4C494E4B,
    BMP_CLRSPACE_IN_SAME_FILE = 0x4D424544
}im_bmp_logical_color_space_v5;

#define BMP_BITCOUNT_SPECIFIED_BY_PNG_OR_JPEG 0
#define BMP_BITCOUNT_MONOCHROME 1
#define BMP_BITCOUNT_16_COLOR_PALETTE 4
#define BMP_BITCOUNT_256_COLOR_PALETTE 8
#define BMP_BITCOUNT_RGB_16 16
#define BMP_BITCOUNT_RGB_24 24
#define BMP_BITCOUNT_RGB_32 32

#define BMP_HEADER_TYPE_CORE 12
#define BMP_HEADER_TYPE_OS2_64 64
#define BMP_HEADER_TYPE_OS2_16 16
#define BMP_HEADER_TYPE_V1 40
#define BMP_HEADER_TYPE_V2 52
#define BMP_HEADER_TYPE_V3 56
#define BMP_HEADER_TYPE_V4 108
#define BMP_HEADER_TYPE_V5 124

typedef struct bitmap_file_header {
  uint16_t type;
  uint32_t size;
  uint16_t reserved1;
  uint16_t reserved2;
  uint32_t bitmap_offset;
} bitmap_file_header;

typedef struct bitmap_header_core {
    uint32_t struct_size;
    uint16_t width;
    uint16_t height;
    uint16_t num_planes;
    uint16_t bit_count;
} bitmap_header_core;

typedef struct bitmap_header_os2_16 {
    uint32_t struct_size;
    uint32_t width;
    uint32_t height;
    uint16_t num_planes;
    uint16_t bit_count;
} bitmap_header_os2_16;

typedef struct bitmap_header_os2_64 {
    uint32_t struct_size;
    uint32_t width;
    uint32_t height;
    uint16_t num_planes;
    uint16_t bit_count;
    uint32_t compression_format;
    uint32_t image_size;
    uint32_t pixels_per_meter_x;
    uint32_t pixels_per_meter_y;
    uint32_t num_color_indices;
    uint32_t num_required_color_indices;

    uint16_t bc2ResUnit;
    uint16_t bc2Reserved;
    uint16_t bc2Orientation;
    uint16_t bc2Halftoning;
    uint32_t bc2HalftoneSize1;
    uint32_t bc2HalftoneSize2;
    uint32_t bc2ColorSpace;
    uint32_t bc2AppData;
} bitmap_header_os2_64;

typedef struct bitmap_header_v1 {
  uint32_t struct_size;
  int32_t  width;
  int32_t  height;
  uint16_t  num_planes;
  uint16_t  bit_count;
  uint32_t compression_format;
  uint32_t image_size;
  int32_t  pixels_per_meter_x;
  int32_t  pixels_per_meter_y;
  uint32_t num_color_indices;
  uint32_t num_required_color_indices;
} bitmap_header_v1;

typedef struct bitmap_header_v2 {
  uint32_t struct_size;
  int32_t  width;
  int32_t  height;
  uint16_t num_planes;
  uint16_t bit_count;
  uint32_t compression_format;
  uint32_t image_size;
  int32_t  pixels_per_meter_x;
  int32_t  pixels_per_meter_y;
  uint32_t num_color_indices;
  uint32_t num_required_color_indices;
  /* these masks are used to extract pixels from the image if the compression is BI_COMP_BITFIELDS */
  uint32_t red_mask;
  uint32_t green_mask;
  uint32_t blue_mask;
} bitmap_header_v2;

typedef struct bitmap_header_v3 {
  uint32_t struct_size;
  int32_t  width;
  int32_t  height;
  uint16_t num_planes;
  uint16_t bit_count;
  uint32_t compression_format;
  uint32_t image_size;
  int32_t  pixels_per_meter_x;
  int32_t  pixels_per_meter_y;
  uint32_t num_color_indices;
  uint32_t num_required_color_indices;
  /* these masks are used to extract pixels from the image if the compression is BI_COMP_BITFIELDS */
  uint32_t red_mask;
  uint32_t green_mask;
  uint32_t blue_mask;
  uint32_t alpha_mask;
} bitmap_header_v3;

typedef struct bitmap_header_v4 {
  uint32_t     struct_size;
  int32_t      width;
  int32_t      height;
  uint16_t     num_planes;
  uint16_t     bit_count;
  uint32_t     compression_format;
  uint32_t     image_size;
  int32_t      pixels_per_meter_x;
  int32_t      pixels_per_meter_y;
  uint32_t     num_color_indices;
  uint32_t     num_required_color_indices;
  /* these masks are used to extract pixels from the image if the compression is BI_COMP_BITFIELDS */
  uint32_t     red_mask;
  uint32_t     green_mask;
  uint32_t     blue_mask;
  uint32_t     alpha_mask;
  uint32_t     colorspace;
  px_clr_crds colorspace_endpoints;
  uint32_t     gamma_red;
  uint32_t     gamma_green;
  uint32_t     gamma_blue;
} bitmap_header_v4;

typedef struct {
  uint32_t     struct_size;
  int32_t      width;
  int32_t      height;
  uint16_t     num_planes; /* must be 1 */
  uint16_t     bit_count;
  uint32_t     compression_format;
  uint32_t     image_size; /* docs say that this is the size of the image buffer if there is JPEG or PNG compression. Not sure if that means size before or after compression */
  int32_t      pixels_per_meter_x;
  int32_t      pixels_per_meter_y;
  uint32_t     num_color_indices; /* specifies number of colors in the pallete. If zero, the image is not palletized */
  uint32_t     num_required_color_indices;
  /* these masks are used to extract pixels from the image if the compression is BI_COMP_BITFIELDS */
  uint32_t     red_mask;
  uint32_t     green_mask;
  uint32_t     blue_mask;
  uint32_t     alpha_mask;

  uint32_t     colorspace;
  px_clr_crds  colorspace_endpoints;
  uint32_t     gamma_red;
  uint32_t     gamma_green;
  uint32_t     gamma_blue;
  uint32_t     rendering_intent;
  uint32_t     color_profile_data;
  uint32_t     color_profile_size;
  uint32_t     reserved;
} bitmap_header_v5;

#include <immintrin.h>

#include <emmintrin.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

unsigned char *im_bmp_copy_data(unsigned char *pixel_offset, int width, int height, int bits_per_pixel, uint32_t compression_format, const uint8_t *palette) {
    if (width == 0 || height == 0) return NULL;
    int abs_height = (height < 0) ? -height : height;
    int top_down = (height < 0);

    size_t bytes_per_pixel = (bits_per_pixel >= 24) ? ((bits_per_pixel + 7)/8) : 3; /* output RGB(A) */
    size_t stride;

    if (bits_per_pixel >= 8)
        stride = ((width * (bits_per_pixel/8) + 3)/4) * 4;
    else
        stride = ((width * bits_per_pixel + 7)/8 + 3)/4*4;

    unsigned char *output = malloc((size_t)width * abs_height * bytes_per_pixel);
    if (!output) return NULL;

    unsigned char *in = pixel_offset;

    for (int row = 0; row < abs_height; row++) {
        unsigned char *dst_row = output + (size_t)((top_down ? row : (abs_height-1-row)) * width * bytes_per_pixel);
        unsigned char *dst = dst_row;
        unsigned char *src = in;

        if (bits_per_pixel <= 8) {
            /* palettized images */
            int x = 0;
            int pixels_per_byte = 8 / bits_per_pixel;
            int mask = (1 << bits_per_pixel) - 1;

            for (; x < width; x++) {
                int byte_index = x / pixels_per_byte;
                int shift = (pixels_per_byte - 1 - (x % pixels_per_byte)) * bits_per_pixel;
                int idx = (src[byte_index] >> shift) & mask;

                dst[0] = palette[idx*3 + 0];
                dst[1] = palette[idx*3 + 1];
                dst[2] = palette[idx*3 + 2];
                if (bytes_per_pixel == 4) dst[3] = 255;
                dst += bytes_per_pixel;
            }
        }
        else if (bytes_per_pixel == 3) {
            /* 24-bit BGR → RGB, scalar unrolled 4 pixels */
            int x = 0;
            for (; x + 3 < width; x += 4) {
                dst[0] = src[2]; dst[1] = src[1]; dst[2] = src[0];
                dst[3] = src[5]; dst[4] = src[4]; dst[5] = src[3];
                dst[6] = src[8]; dst[7] = src[7]; dst[8] = src[6];
                dst[9] = src[11]; dst[10] = src[10]; dst[11] = src[9];

                src += 12;
                dst += 12;
            }
            /* handle the leftovers without unrolling */
            for (; x < width; x++) {
                dst[0] = src[2]; dst[1] = src[1]; dst[2] = src[0];
                src += 3;
                dst += 3;
            }
        }
        else if (bytes_per_pixel == 4) {
            /* 32-bit BGRA → RGBA, SSE2 */
            int x = 0;
            const __m128i alpha_set = _mm_set1_epi32(0xFF000000);
            for (; x + 3 < width; x += 4) {
                __m128i v = _mm_loadu_si128((__m128i*)src);

                const __m128i mask_r = _mm_set1_epi32(0x000000FF);
                const __m128i mask_b = _mm_set1_epi32(0x00FF0000);
                const __m128i mask_mid = _mm_set1_epi32(0xFF00FF00);

                __m128i r = _mm_and_si128(v, mask_r);
                __m128i b = _mm_and_si128(v, mask_b);
                __m128i mid = _mm_and_si128(v, mask_mid);

                r = _mm_slli_epi32(r, 16);
                b = _mm_srli_epi32(b, 16);

                __m128i outv = _mm_or_si128(mid, _mm_or_si128(r, b));
                outv = _mm_or_si128(outv, alpha_set);

                _mm_storeu_si128((__m128i*)dst, outv);

                src += 16;
                dst += 16;
            }
            /* handle the leftovers scalar */
            for (; x < width; x++) {
                dst[0] = src[2];
                dst[1] = src[1];
                dst[2] = src[0];
                dst[3] = 255;
                src += 4;
                dst += 4;
            }
        }

        in += stride;
    }

    return output;
}

unsigned char *im_bmp_load(unsigned char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    unsigned char *at = image_file;
    unsigned char *end_of_file = image_file + file_size;

    bitmap_file_header file_header;
    file_header.type        = consume_uint16(&at, end_of_file);
    file_header.size        = consume_uint32(&at, end_of_file);
    file_header.reserved1   = consume_uint16(&at, end_of_file);
    file_header.reserved2   = consume_uint16(&at, end_of_file);
    file_header.bitmap_offset = consume_uint32(&at, end_of_file);

    unsigned char *pixel_offset = (unsigned char *)image_file + file_header.bitmap_offset;

    uint32_t *dib_header_size = (uint32_t*)at;
    size_t bits_per_pixel = 0;
    uint8_t rgb_palette[256*3] = {0};
    int palette_entries = 0;
    uint32_t compression_format = 0;

    switch(*dib_header_size) {

        case BMP_HEADER_TYPE_CORE: {
            bitmap_header_core header = *(bitmap_header_core*)consume(&at, end_of_file, sizeof(bitmap_header_core));
            *width = header.width;
            *height = header.height;
            bits_per_pixel = header.bit_count;

            if(bits_per_pixel <= 8) {
                palette_entries = 1 << bits_per_pixel;
                unsigned char *bmp_palette = (unsigned char*)at;
                for(int i = 0; i < palette_entries; i++) {
                    rgb_palette[i*3 + 0] = bmp_palette[i*4 + 2]; // R
                    rgb_palette[i*3 + 1] = bmp_palette[i*4 + 1]; // G
                    rgb_palette[i*3 + 2] = bmp_palette[i*4 + 0]; // B
                }
            }
            break;
        }

        case BMP_HEADER_TYPE_OS2_16: {
            bitmap_header_os2_16 header = *(bitmap_header_os2_16*)consume(&at, end_of_file, sizeof(bitmap_header_os2_16));
            *width = header.width;
            *height = header.height;
            bits_per_pixel = header.bit_count;

            if(bits_per_pixel <= 8) {
                palette_entries = 1u << bits_per_pixel;
                unsigned char *bmp_palette = (unsigned char*)at;
                for(int i = 0; i < palette_entries; i++) {
                    rgb_palette[i*3 + 0] = bmp_palette[i*4 + 2];
                    rgb_palette[i*3 + 1] = bmp_palette[i*4 + 1];
                    rgb_palette[i*3 + 2] = bmp_palette[i*4 + 0];
                }
            }
            break;
        }

        case BMP_HEADER_TYPE_OS2_64: {
            bitmap_header_os2_64 header = *(bitmap_header_os2_64*)consume(&at, end_of_file, sizeof(bitmap_header_os2_64));
            *width = header.width;
            *height = header.height;
            bits_per_pixel = header.bit_count;
            compression_format = header.compression_format;

            if(bits_per_pixel <= 8) {
                palette_entries = header.num_color_indices ? header.num_color_indices : 1u << bits_per_pixel;
                unsigned char *bmp_palette = (unsigned char*)at;
                for(int i = 0; i < palette_entries; i++) {
                    rgb_palette[i*3 + 0] = bmp_palette[i*4 + 2];
                    rgb_palette[i*3 + 1] = bmp_palette[i*4 + 1];
                    rgb_palette[i*3 + 2] = bmp_palette[i*4 + 0];
                }
            }
            break;
        }

        case BMP_HEADER_TYPE_V1: {
            bitmap_header_v1 header = *(bitmap_header_v1*)consume(&at, end_of_file, sizeof(bitmap_header_v1));
            *width = header.width;
            *height = header.height;
            bits_per_pixel = header.bit_count;
            compression_format = header.compression_format;

            if(bits_per_pixel <= 8) {
                palette_entries = header.num_color_indices ? header.num_color_indices : 1u << bits_per_pixel;
                unsigned char *bmp_palette = (unsigned char*)at;
                for(int i = 0; i < palette_entries; i++) {
                    rgb_palette[i*3 + 0] = bmp_palette[i*4 + 2];
                    rgb_palette[i*3 + 1] = bmp_palette[i*4 + 1];
                    rgb_palette[i*3 + 2] = bmp_palette[i*4 + 0];
                }
            }
            break;
        }

        case BMP_HEADER_TYPE_V2: {
            bitmap_header_v2 header = *(bitmap_header_v2*)consume(&at, end_of_file, sizeof(bitmap_header_v2));
            *width = header.width;
            *height = header.height;
            bits_per_pixel = header.bit_count;
            compression_format = header.compression_format;

            if(bits_per_pixel <= 8) {
                palette_entries = header.num_color_indices ? header.num_color_indices : 1u << bits_per_pixel;
                unsigned char *bmp_palette = (unsigned char*)at;
                for(int i = 0; i < palette_entries; i++) {
                    rgb_palette[i*3 + 0] = bmp_palette[i*4 + 2];
                    rgb_palette[i*3 + 1] = bmp_palette[i*4 + 1];
                    rgb_palette[i*3 + 2] = bmp_palette[i*4 + 0];
                }
            }
            break;
        }

        case BMP_HEADER_TYPE_V3: {
            bitmap_header_v3 header = *(bitmap_header_v3*)consume(&at, end_of_file, sizeof(bitmap_header_v3));
            *width = header.width;
            *height = header.height;
            bits_per_pixel = header.bit_count;
            compression_format = header.compression_format;

            if(bits_per_pixel <= 8) {
                palette_entries = header.num_color_indices ? header.num_color_indices : 1u << bits_per_pixel;
                unsigned char *bmp_palette = (unsigned char*)at;
                for(int i = 0; i < palette_entries; i++) {
                    rgb_palette[i*3 + 0] = bmp_palette[i*4 + 2];
                    rgb_palette[i*3 + 1] = bmp_palette[i*4 + 1];
                    rgb_palette[i*3 + 2] = bmp_palette[i*4 + 0];
                }
            }
            break;
        }

        case BMP_HEADER_TYPE_V4: {
            bitmap_header_v4 header = *(bitmap_header_v4*)consume(&at, end_of_file, sizeof(bitmap_header_v4));
            *width = header.width;
            *height = header.height;
            bits_per_pixel = header.bit_count;
            compression_format = header.compression_format;

            if(bits_per_pixel <= 8) {
                palette_entries = header.num_color_indices ? header.num_color_indices : 1u << bits_per_pixel;
                unsigned char *bmp_palette = (unsigned char*)at;
                for(int i = 0; i < palette_entries; i++) {
                    rgb_palette[i*3 + 0] = bmp_palette[i*4 + 2];
                    rgb_palette[i*3 + 1] = bmp_palette[i*4 + 1];
                    rgb_palette[i*3 + 2] = bmp_palette[i*4 + 0];
                }
            }
            break;
        }

        case BMP_HEADER_TYPE_V5: {
            bitmap_header_v5 header = *(bitmap_header_v5*)consume(&at, end_of_file, sizeof(bitmap_header_v5));
            *width = header.width;
            *height = header.height;
            bits_per_pixel = header.bit_count;
            compression_format = header.compression_format;

            if(bits_per_pixel <= 8) {
                palette_entries = header.num_color_indices ? header.num_color_indices : 1u << bits_per_pixel;
                unsigned char *bmp_palette = (unsigned char*)at;
                for(int i = 0; i < palette_entries; i++) {
                    rgb_palette[i*3 + 0] = bmp_palette[i*4 + 2];
                    rgb_palette[i*3 + 1] = bmp_palette[i*4 + 1];
                    rgb_palette[i*3 + 2] = bmp_palette[i*4 + 0];
                }
            }
            break;
        }

        default:
            IM_ERR("Unsupported BMP header size: %u\n", *dib_header_size);
            return NULL;
    }

    return im_bmp_copy_data(pixel_offset, *width, *height, bits_per_pixel, compression_format, (bits_per_pixel <= 8) ? rgb_palette : NULL);
}
/*
 * Complete PSD loader implementation
 * Replace the existing im_psd_load function with this code
 */

typedef enum {
    IM_PSD_COMP_RAW = 0,
    IM_PSD_COMP_RLE = 1,
    IM_PSD_COMP_ZIP_NO_PREDICTION = 2,
    IM_PSD_COMP_ZIP_WITH_PREDICTION = 3,
} im_psd_compression_types;

typedef enum {
    IM_PSD_COLOR_BITMAP = 0,
    IM_PSD_COLOR_GRAYSCALE = 1,
    IM_PSD_COLOR_INDEXED = 2,
    IM_PSD_COLOR_RGB = 3,
    IM_PSD_COLOR_CMYK = 4,
    IM_PSD_COLOR_MULTICHANNEL = 7,
    IM_PSD_COLOR_DUOTONE = 8,
    IM_PSD_COLOR_LAB = 9,
} IM_PSD_COLOR_modes;

/* PackBits RLE decompression for PSD files */
static int im_psd_decode_rle_row(unsigned char *dst, size_t dst_len, unsigned char **src, unsigned char *src_end) {
    size_t written = 0;
    
    while (written < dst_len && *src < src_end) {
        int8_t header = (int8_t)(*(*src)++);
        
        if (header >= 0) {
            /* Literal run: copy (header + 1) bytes */
            int count = header + 1;
            for (int i = 0; i < count && written < dst_len && *src < src_end; i++) {
                dst[written++] = *(*src)++;
            }
        } else if (header != -128) {
            /* Repeat run: repeat next byte (1 - header) times */
            int count = 1 - header;
            if (*src >= src_end) break;
            unsigned char value = *(*src)++;
            for (int i = 0; i < count && written < dst_len; i++) {
                dst[written++] = value;
            }
        }
        /* header == -128 is a no-op */
    }
    
    return (written == dst_len) ? 0 : -1;
}

/* Convert planar channel data to interleaved RGB(A) */
static void im_psd_interleave_channels_8bit(unsigned char *output, 
                                             unsigned char **channels,
                                             int channel_count,
                                             size_t pixel_count) {
    for (size_t i = 0; i < pixel_count; i++) {
        for (int c = 0; c < channel_count; c++) {
            output[i * channel_count + c] = channels[c][i];
        }
    }
}

/* Convert 16-bit big-endian planar to 8-bit interleaved */
static void im_psd_interleave_channels_16bit(unsigned char *output,
                                              unsigned char **channels,
                                              int channel_count,
                                              size_t pixel_count) {
    for (size_t i = 0; i < pixel_count; i++) {
        for (int c = 0; c < channel_count; c++) {
            /* 16-bit samples are big-endian, take high byte for 8-bit output */
            uint16_t val = (channels[c][i * 2] << 8) | channels[c][i * 2 + 1];
            output[i * channel_count + c] = (unsigned char)(val >> 8);
        }
    }
}

/* Convert CMYK to RGB */
static void im_psd_cmyk_to_rgb(unsigned char *output, unsigned char **channels,
                                size_t pixel_count, int bits_per_channel) {
    if (bits_per_channel == 8) {
        for (size_t i = 0; i < pixel_count; i++) {
            float c = channels[0][i] / 255.0f;
            float m = channels[1][i] / 255.0f;
            float y = channels[2][i] / 255.0f;
            float k = channels[3][i] / 255.0f;
            
            /* CMYK to RGB conversion */
            output[i * 3 + 0] = (unsigned char)((1.0f - c) * (1.0f - k) * 255.0f);
            output[i * 3 + 1] = (unsigned char)((1.0f - m) * (1.0f - k) * 255.0f);
            output[i * 3 + 2] = (unsigned char)((1.0f - y) * (1.0f - k) * 255.0f);
        }
    } else if (bits_per_channel == 16) {
        for (size_t i = 0; i < pixel_count; i++) {
            uint16_t c16 = (channels[0][i * 2] << 8) | channels[0][i * 2 + 1];
            uint16_t m16 = (channels[1][i * 2] << 8) | channels[1][i * 2 + 1];
            uint16_t y16 = (channels[2][i * 2] << 8) | channels[2][i * 2 + 1];
            uint16_t k16 = (channels[3][i * 2] << 8) | channels[3][i * 2 + 1];
            
            float c = c16 / 65535.0f;
            float m = m16 / 65535.0f;
            float y = y16 / 65535.0f;
            float k = k16 / 65535.0f;
            
            output[i * 3 + 0] = (unsigned char)((1.0f - c) * (1.0f - k) * 255.0f);
            output[i * 3 + 1] = (unsigned char)((1.0f - m) * (1.0f - k) * 255.0f);
            output[i * 3 + 2] = (unsigned char)((1.0f - y) * (1.0f - k) * 255.0f);
        }
    }
}

float im_clamp_float(float number, float min, float max) {
    if(number > max) {
        number = max;
    } else if (number < min) {
        number = min;
    }
    return number;
}

/* Convert Lab to RGB */
static void im_psd_lab_to_rgb(unsigned char *output, unsigned char **channels,
                               size_t pixel_count, int bits_per_channel) {
    for (size_t i = 0; i < pixel_count; i++) {
        float L, a, b;
        
        if (bits_per_channel == 8) {
            /* PSD Lab: L is 0-255 mapped to 0-100, a and b are 0-255 mapped to -128 to 127 */
            L = (channels[0][i] / 255.0f) * 100.0f;
            a = channels[1][i] - 128.0f;
            b = channels[2][i] - 128.0f;
        } else {
            uint16_t L16 = (channels[0][i * 2] << 8) | channels[0][i * 2 + 1];
            uint16_t a16 = (channels[1][i * 2] << 8) | channels[1][i * 2 + 1];
            uint16_t b16 = (channels[2][i * 2] << 8) | channels[2][i * 2 + 1];
            
            L = (L16 / 65535.0f) * 100.0f;
            a = (a16 / 65535.0f) * 255.0f - 128.0f;
            b = (b16 / 65535.0f) * 255.0f - 128.0f;
        }
        
        /* Lab to XYZ */
        float fy = (L + 16.0f) / 116.0f;
        float fx = a / 500.0f + fy;
        float fz = fy - b / 200.0f;
        
        float x, y, z;
        float delta = 6.0f / 29.0f;
        
        if (fx > delta) x = fx * fx * fx;
        else x = (fx - 16.0f / 116.0f) * 3.0f * delta * delta;
        
        if (fy > delta) y = fy * fy * fy;
        else y = (fy - 16.0f / 116.0f) * 3.0f * delta * delta;
        
        if (fz > delta) z = fz * fz * fz;
        else z = (fz - 16.0f / 116.0f) * 3.0f * delta * delta;
        
        /* D65 white point */
        x *= 0.95047f;
        y *= 1.0f;
        z *= 1.08883f;
        
        /* XYZ to sRGB */
        float r =  3.2404542f * x - 1.5371385f * y - 0.4985314f * z;
        float g = -0.9692660f * x + 1.8760108f * y + 0.0415560f * z;
        float bl = 0.0556434f * x - 0.2040259f * y + 1.0572252f * z;
        
        /* Clamp and convert to 8-bit */
        r = im_clamp_float(r, 0, 1);
        g = im_clamp_float(g, 0, 1);
        bl = im_clamp_float(bl, 0, 1);
        
        output[i * 3 + 0] = (unsigned char)(r * 255.0f);
        output[i * 3 + 1] = (unsigned char)(g * 255.0f);
        output[i * 3 + 2] = (unsigned char)(bl * 255.0f);
    }
}

unsigned char *im_psd_load(unsigned char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    unsigned char *at = image_file;
    unsigned char *end_of_file = image_file + file_size;
    
    /* Validate minimum file size */
    if (file_size < 26) {
        IM_ERR("PSD file too small to contain valid header");
        return NULL;
    }
    
    /* ========== FILE HEADER SECTION (26 bytes) ========== */
    
    /* Skip signature "8BPS" - already validated */
    consume(&at, end_of_file, 4);
    
    /* Version: 1 = PSD, 2 = PSB (large document) */
    uint16_t version = consume_and_swap_uint16(&at, end_of_file);
    if (version != 1 && version != 2) {
        IM_ERR("Unsupported PSD version: %d", version);
        return NULL;
    }
    
    /* Skip 6 reserved bytes */
    consume(&at, end_of_file, 6);
    
    /* Number of channels (1-56) */
    uint16_t channel_count = consume_and_swap_uint16(&at, end_of_file);
    if (channel_count < 1 || channel_count > 56) {
        IM_ERR("Invalid PSD channel count: %d", channel_count);
        return NULL;
    }
    
    /* Image dimensions */
    uint32_t image_height = consume_and_swap_uint32(&at, end_of_file);
    uint32_t image_width = consume_and_swap_uint32(&at, end_of_file);
    
    /* Validate dimensions */
    if (image_width == 0 || image_height == 0) {
        IM_ERR("Invalid PSD dimensions: %dx%d", image_width, image_height);
        return NULL;
    }
    
    /* For PSD (v1), max is 30000x30000. For PSB (v2), max is 300000x300000 */
    uint32_t max_dim = (version == 1) ? 30000 : 300000;
    if (image_width > max_dim || image_height > max_dim) {
        IM_ERR("PSD dimensions exceed maximum: %dx%d", image_width, image_height);
        return NULL;
    }
    
    /* Bits per channel: 1, 8, 16, or 32 */
    uint16_t bits_per_channel = consume_and_swap_uint16(&at, end_of_file);
    if (bits_per_channel != 1 && bits_per_channel != 8 && 
        bits_per_channel != 16 && bits_per_channel != 32) {
        IM_ERR("Unsupported PSD bit depth: %d", bits_per_channel);
        return NULL;
    }
    
    /* Color mode */
    uint16_t color_mode = consume_and_swap_uint16(&at, end_of_file);
    
    *width = (int)image_width;
    *height = (int)image_height;
    
    /* ========== COLOR MODE DATA SECTION ========== */
    
    uint32_t color_data_length = consume_and_swap_uint32(&at, end_of_file);
    
    /* Store palette for indexed color mode */
    unsigned char *palette = NULL;
    if (color_mode == IM_PSD_COLOR_INDEXED && color_data_length >= 768) {
        palette = (unsigned char *)malloc(768);
        if (palette) {
            im_memcpy(palette, at, 768);
        }
    }
    
    consume(&at, end_of_file, color_data_length);
    
    /* ========== IMAGE RESOURCES SECTION ========== */
    
    uint32_t image_resources_length = consume_and_swap_uint32(&at, end_of_file);
    consume(&at, end_of_file, image_resources_length);
    
    /* ========== LAYER AND MASK INFORMATION SECTION ========== */
    
    if (version == 1) {
        uint32_t layer_mask_length = consume_and_swap_uint32(&at, end_of_file);
        consume(&at, end_of_file, layer_mask_length);
    } else {
        /* PSB uses 8-byte length */
        uint32_t high = consume_and_swap_uint32(&at, end_of_file);
        uint32_t low = consume_and_swap_uint32(&at, end_of_file);
        uint64_t layer_mask_length = ((uint64_t)high << 32) | low;
        consume(&at, end_of_file, (size_t)layer_mask_length);
    }
    
    /* ========== IMAGE DATA SECTION ========== */
    
    if (at + 2 > end_of_file) {
        IM_ERR("PSD file truncated before image data");
        if (palette) free(palette);
        return NULL;
    }
    
    uint16_t compression_method = consume_and_swap_uint16(&at, end_of_file);
    
    size_t pixel_count = (size_t)image_width * image_height;
    size_t bytes_per_channel_per_pixel = (bits_per_channel + 7) / 8;
    size_t channel_size = pixel_count * bytes_per_channel_per_pixel;
    
    /* Allocate channel buffers */
    unsigned char **channel_data = (unsigned char **)malloc(channel_count * sizeof(unsigned char *));
    if (!channel_data) {
        if (palette) free(palette);
        return NULL;
    }
    
    for (int i = 0; i < channel_count; i++) {
        channel_data[i] = (unsigned char *)malloc(channel_size);
        if (!channel_data[i]) {
            for (int j = 0; j < i; j++) free(channel_data[j]);
            free(channel_data);
            if (palette) free(palette);
            return NULL;
        }
    }
    
    int decode_error = 0;
    
    switch (compression_method) {
        case IM_PSD_COMP_RAW: {
            /* Raw data: channels stored sequentially in planar format */
            for (int c = 0; c < channel_count && !decode_error; c++) {
                if (at + channel_size > end_of_file) {
                    decode_error = 1;
                    break;
                }
                im_memcpy(channel_data[c], at, channel_size);
                at += channel_size;
            }
            break;
        }
        
        case IM_PSD_COMP_RLE: {
            /* RLE compressed: row byte counts followed by compressed data */
            size_t row_count = (size_t)image_height * channel_count;
            size_t row_count_size = row_count * ((version == 1) ? 2 : 4);
            
            if (at + row_count_size > end_of_file) {
                decode_error = 1;
                break;
            }
            
            /* Read row byte counts */
            uint32_t *row_lengths = (uint32_t *)malloc(row_count * sizeof(uint32_t));
            if (!row_lengths) {
                decode_error = 1;
                break;
            }
            
            unsigned char *row_len_ptr = at;
            for (size_t i = 0; i < row_count; i++) {
                if (version == 1) {
                    row_lengths[i] = (row_len_ptr[0] << 8) | row_len_ptr[1];
                    row_len_ptr += 2;
                } else {
                    row_lengths[i] = ((uint32_t)row_len_ptr[0] << 24) |
                                     ((uint32_t)row_len_ptr[1] << 16) |
                                     ((uint32_t)row_len_ptr[2] << 8) |
                                     ((uint32_t)row_len_ptr[3]);
                    row_len_ptr += 4;
                }
            }
            at += row_count_size;
            
            /* Decompress each row using the byte counts */
            size_t row_idx = 0;
            size_t bytes_per_row = (size_t)image_width * bytes_per_channel_per_pixel;
            
            for (int c = 0; c < channel_count && !decode_error; c++) {
                for (uint32_t y = 0; y < image_height && !decode_error; y++) {
                    uint32_t compressed_len = row_lengths[row_idx];
                    
                    if (at + compressed_len > end_of_file) {
                        decode_error = 1;
                        break;
                    }
                    
                    unsigned char *dst = channel_data[c] + y * bytes_per_row;
                    unsigned char *src = at;
                    unsigned char *src_end = at + compressed_len;
                    
                    if (im_psd_decode_rle_row(dst, bytes_per_row, &src, src_end) != 0) {
                        decode_error = 1;
                    }
                    
                    /* Advance by the exact compressed length, not by how much we read */
                    at += compressed_len;
                    row_idx++;
                }
            }
            
            free(row_lengths);
            break;
        }
        
        case IM_PSD_COMP_ZIP_NO_PREDICTION:
        case IM_PSD_COMP_ZIP_WITH_PREDICTION: {
            /* PSD uses raw deflate (no zlib header) 
             * ZIP-compressed data is stored row-interleaved, not planar */
            
            size_t bytes_per_row = (size_t)image_width * bytes_per_channel_per_pixel * channel_count;
            size_t total_size = bytes_per_row * image_height;
            
            unsigned char *all_data = (unsigned char *)malloc(total_size);
            if (!all_data) {
                decode_error = 1;
                break;
            }
            
            /* Decompress all data - raw deflate, no zlib header */
            size_t compressed_size = (size_t)(end_of_file - at);
            int64_t result = im_inflate(at, compressed_size, all_data, total_size);
            
            if (result < 0 || (size_t)result != total_size) {
                IM_ERR("PSD ZIP: decompression failed (got %lld, expected %zu)", 
                       (long long)result, total_size);
                free(all_data);
                decode_error = 1;
                break;
            }
            
            /* Apply delta prediction if needed (applied to raw bytes, row by row) */
            if (compression_method == IM_PSD_COMP_ZIP_WITH_PREDICTION) {
                for (uint32_t y = 0; y < image_height; y++) {
                    unsigned char *row = all_data + y * bytes_per_row;
                    
                    if (bits_per_channel == 8) {
                        for (size_t x = 1; x < bytes_per_row; x++) {
                            row[x] += row[x - 1];
                        }
                    } else if (bits_per_channel == 16) {
                        for (size_t x = 2; x < bytes_per_row; x += 2) {
                            uint16_t prev = ((uint16_t)row[x - 2] << 8) | row[x - 1];
                            uint16_t curr = ((uint16_t)row[x] << 8) | row[x + 1];
                            uint16_t val = curr + prev;
                            row[x] = (val >> 8) & 0xFF;
                            row[x + 1] = val & 0xFF;
                        }
                    } else if (bits_per_channel == 32) {
                        for (size_t x = 4; x < bytes_per_row; x += 4) {
                            uint32_t prev = ((uint32_t)row[x - 4] << 24) |
                                           ((uint32_t)row[x - 3] << 16) |
                                           ((uint32_t)row[x - 2] << 8) |
                                           ((uint32_t)row[x - 1]);
                            uint32_t curr = ((uint32_t)row[x] << 24) |
                                           ((uint32_t)row[x + 1] << 16) |
                                           ((uint32_t)row[x + 2] << 8) |
                                           ((uint32_t)row[x + 3]);
                            uint32_t val = curr + prev;
                            row[x] = (val >> 24) & 0xFF;
                            row[x + 1] = (val >> 16) & 0xFF;
                            row[x + 2] = (val >> 8) & 0xFF;
                            row[x + 3] = val & 0xFF;
                        }
                    }
                }
            }
            
            /* De-interleave into separate channel buffers */
            size_t channel_bytes_per_row = (size_t)image_width * bytes_per_channel_per_pixel;
            for (uint32_t y = 0; y < image_height; y++) {
                unsigned char *src_row = all_data + y * bytes_per_row;
                for (int c = 0; c < channel_count; c++) {
                    unsigned char *dst_row = channel_data[c] + y * channel_bytes_per_row;
                    for (uint32_t x = 0; x < image_width; x++) {
                        for (size_t b = 0; b < bytes_per_channel_per_pixel; b++) {
                            dst_row[x * bytes_per_channel_per_pixel + b] = 
                                src_row[x * channel_count * bytes_per_channel_per_pixel + 
                                        c * bytes_per_channel_per_pixel + b];
                        }
                    }
                }
            }
            
            free(all_data);
            break;
        }
        
        default:
            IM_ERR("Unknown PSD compression method: %d", compression_method);
            decode_error = 1;
            break;
    }
    
    if (decode_error) {
        for (int i = 0; i < channel_count; i++) {
            if (channel_data[i]) free(channel_data[i]);
        }
        free(channel_data);
        if (palette) free(palette);
        return NULL;
    }
    
    /* ========== CONVERT TO OUTPUT FORMAT ========== */
    
    unsigned char *output = NULL;
    int output_channels = 0;
    
    switch (color_mode) {
        case IM_PSD_COLOR_BITMAP: {
            /* 1-bit bitmap - expand to 8-bit grayscale */
            output_channels = 1;
            output = (unsigned char *)malloc(pixel_count);
            if (output) {
                for (size_t i = 0; i < pixel_count; i++) {
                    size_t byte_idx = i / 8;
                    int bit_idx = 7 - (i % 8);
                    int bit = (channel_data[0][byte_idx] >> bit_idx) & 1;
                    output[i] = bit ? 0 : 255; /* 1 = black, 0 = white in PSD */
                }
            }
            break;
        }
        
        case IM_PSD_COLOR_GRAYSCALE: {
            /* Grayscale, possibly with alpha */
            output_channels = (channel_count >= 2) ? 2 : 1;
            output = (unsigned char *)malloc(pixel_count * output_channels);
            if (output) {
                if (bits_per_channel == 8) {
                    im_psd_interleave_channels_8bit(output, channel_data, 
                                                    output_channels, pixel_count);
                } else if (bits_per_channel == 16) {
                    im_psd_interleave_channels_16bit(output, channel_data,
                                                     output_channels, pixel_count);
                } else if (bits_per_channel == 32) {
                    /* 32-bit float - take first byte of big-endian float */
                    for (size_t i = 0; i < pixel_count; i++) {
                        for (int c = 0; c < output_channels; c++) {
                            /* Simplified: just take high byte */
                            output[i * output_channels + c] = channel_data[c][i * 4];
                        }
                    }
                }
            }
            break;
        }
        
        case IM_PSD_COLOR_INDEXED: {
            /* Indexed color - convert to RGB */
            output_channels = 3;
            output = (unsigned char *)malloc(pixel_count * 3);
            if (output && palette) {
                for (size_t i = 0; i < pixel_count; i++) {
                    uint8_t idx = channel_data[0][i];
                    /* PSD palette is stored as R[256], G[256], B[256] */
                    output[i * 3 + 0] = palette[idx];
                    output[i * 3 + 1] = palette[idx + 256];
                    output[i * 3 + 2] = palette[idx + 512];
                }
            }
            break;
        }
        
        case IM_PSD_COLOR_RGB: {
            /* RGB, possibly with alpha */
            output_channels = (channel_count >= 4) ? 4 : 3;
            output = (unsigned char *)malloc(pixel_count * output_channels);
            if (output) {
                if (bits_per_channel == 8) {
                    im_psd_interleave_channels_8bit(output, channel_data,
                                                    output_channels, pixel_count);
                } else if (bits_per_channel == 16) {
                    im_psd_interleave_channels_16bit(output, channel_data,
                                                     output_channels, pixel_count);
                } else if (bits_per_channel == 32) {
                    /* 32-bit float HDR - simplified conversion */
                    for (size_t i = 0; i < pixel_count; i++) {
                        for (int c = 0; c < output_channels; c++) {
                            /* Read big-endian float, clamp to 0-1, convert to 8-bit */
                            uint32_t bits = ((uint32_t)channel_data[c][i * 4] << 24) |
                                           ((uint32_t)channel_data[c][i * 4 + 1] << 16) |
                                           ((uint32_t)channel_data[c][i * 4 + 2] << 8) |
                                           ((uint32_t)channel_data[c][i * 4 + 3]);
                            float f;
                            im_memcpy(&f, &bits, sizeof(float));
                            if (f < 0) f = 0;
                            if (f > 1) f = 1;
                            output[i * output_channels + c] = (unsigned char)(f * 255.0f);
                        }
                    }
                }
            }
            break;
        }
        
        case IM_PSD_COLOR_CMYK: {
            /* CMYK - convert to RGB */
            output_channels = 3;
            output = (unsigned char *)malloc(pixel_count * 3);
            if (output && channel_count >= 4) {
                im_psd_cmyk_to_rgb(output, channel_data, pixel_count, bits_per_channel);
            }
            break;
        }
        
        case IM_PSD_COLOR_LAB: {
            /* Lab - convert to RGB */
            output_channels = 3;
            output = (unsigned char *)malloc(pixel_count * 3);
            if (output && channel_count >= 3) {
                im_psd_lab_to_rgb(output, channel_data, pixel_count, bits_per_channel);
            }
            break;
        }
        
        case IM_PSD_COLOR_DUOTONE:
        case IM_PSD_COLOR_MULTICHANNEL: {
            /* Treat as grayscale */
            output_channels = 1;
            output = (unsigned char *)malloc(pixel_count);
            if (output) {
                if (bits_per_channel == 8) {
                    im_memcpy(output, channel_data[0], pixel_count);
                } else if (bits_per_channel == 16) {
                    for (size_t i = 0; i < pixel_count; i++) {
                        output[i] = channel_data[0][i * 2]; /* High byte */
                    }
                }
            }
            break;
        }
        
        default:
            IM_ERR("Unsupported PSD color mode: %d", color_mode);
            break;
    }
    
    /* Cleanup */
    for (int i = 0; i < channel_count; i++) {
        free(channel_data[i]);
    }
    free(channel_data);
    if (palette) free(palette);
    
    *num_channels = output_channels;
    
    return output;
}

IM_API unsigned char *im_load(const char *image_path, int *width, int *height, int *number_of_channels, int desired_channels) {

    size_t file_size = 0;
    unsigned char *image_file = im__read_entire_file(image_path, &file_size);

    if(!image_file) {
        IM_ERR("ERROR: Failed to read image file from disk.");
        return NULL;
    }

    if(!file_size) {
        IM_ERR("ERROR: size of image file is 0.");
        free(image_file);
        return NULL;
    }

    uint8_t file_sig[8] = {0};
    unsigned char *at = image_file;
    unsigned char *end_of_file = image_file + file_size;

    for(int i = 0; i < 8; i++) {
        if(at < end_of_file) {
            im_memcpy(file_sig + i, at++, 1);
        } else {
            break;
        }
    }

    im_detect_cpu_features();

    unsigned char *pixels = NULL;

    if(im_memcmp(im_png_sig, file_sig, PNG_SIG_LEN) == 0) {
        pixels = im_png_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "BM", 2) == 0) {
        pixels = im_bmp_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "8BPS", 4) == 0) {
        pixels = im_psd_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "P1", 2) == 0) {
        pixels = im_p1_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "P2", 2) == 0) {
        pixels = im_p2_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "P3", 2) == 0) {
        pixels = im_p3_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "P4", 2) == 0) {
        pixels = im_p4_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "P5", 2) == 0) {
        pixels = im_p5_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "P6", 2) == 0) {
        pixels = im_p6_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else {
        IM_ERR("ERROR: File signature does not match any known image formats.\n");
        free(image_file);
        return NULL;
    }

    free(image_file);

    if (pixels && im_flip_vertically_flag) {
        im_flip_vertically(pixels, *width, *height, *number_of_channels);
    }

    return pixels;
}
#endif // IM_IMPL
