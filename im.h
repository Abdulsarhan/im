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

#ifdef __cplusplus
}
#endif

#endif

#ifdef IM_IMPLEMENTATION
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <float.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h> // for testing only, should be removed in prod.

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

#ifndef IM_NO_INFO
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
    char *png_file;
    char *at; // newer variable used for parsing
    char *end_of_file; // we use at + end of file to figure out where we are, and where the end is so that we don't go over.
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
    unsigned char *png_pixels; /* the actual pixels of the image, uncompressed. */
}im_png_info;

uint8_t im_png_sig[PNG_SIG_LEN] = {137, 80, 78, 71, 13, 10, 26, 10};

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

char *im__read_entire_file(const char *file_path, size_t *bytes_read) {
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

    if (file_size.QuadPart > SIZE_MAX) {
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
    return buffer;
#endif
}

void im_png_print_bytes(void *bytes_in, size_t len) {
    uint8_t *bytes = bytes_in;
    for(size_t i = 0; i < len; i++) {
        printf("%u ", bytes[i]);
    }
    printf("\n");
}

void im_png_print_string(const char* str, size_t len) {
    size_t i;
    for(i = 0; i < len; i++) {
        printf("%c ", str[i]);
    }
    printf("\n");
}

//#define consume(at, end_of_file, size) (consume_size(at, end_of_file, size))

void *consume(char **at, char *end_of_file, size_t size) {
    void *orig = *at;
    if(*at + size <= end_of_file) {
        *at += size;
        return orig;
    }
    fprintf(stderr, "Error: %s(), will not read past end of file.", __func__);
    return orig;
}

void endian_swap(uint32_t *start) {
    uint32_t value = *start;
    value = (value << 24) | (value << 8) & 0x00FF0000 | (value >> 8) & 0x0000FF00 | (value >> 24);
    *start = value;
}

// this function simply assumes that you will pass in the start of the uint32_t using the at.
void *consume_and_endian_swap(char **at, char *end_of_file, size_t size) {
    void *value = consume(at, end_of_file, size);
    endian_swap(value);
    return value;
}

size_t im_ceil(size_t x, size_t y) {
    return (x + y - 1) / y;
}

void im_png_parse_chunk_IHDR(im_png_info *info) {
    uint32_t length = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("Length: %d\n", length);
    if(length != 13u){
        IM_ERR("Length section of ihdr chunk is not 13.");
    }

    char *chunk_type = (char*)consume(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("chunk_type: %.*s\n", 4, chunk_type);

    if(!info->first_ihdr) IM_ERR("Multiple IHDR.");

    info->width = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    info->height = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    info->bits_per_channel = *(uint32_t*)consume(&info->at, info->end_of_file, 1);
    info->color_type = *(uint32_t*)consume(&info->at, info->end_of_file, 1);
    info->compression_method = *(uint32_t*)consume(&info->at, info->end_of_file, 1);
    info->filter_method = *(uint32_t*)consume(&info->at, info->end_of_file, 1);
    info->interlace_method = *(uint32_t*)consume(&info->at, info->end_of_file, 1);

    uint32_t *crc = (uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));

#ifndef IM_NO_ERRORS
    if(info->color_type == 1 || info->color_type > 6) {
        IM_ERR("Invalid color type. Expected 0, 2, 3, 4, or 6, got: %u", info->color_type);
    }

    switch(info->color_type) {
        case 0:
            if(info->bits_per_channel !=1 && info->bits_per_channel !=2 && info->bits_per_channel !=4 && info->bits_per_channel !=8 && info->bits_per_channel !=16)
                IM_ERR("Invalid bit depth for color type 0. Expected 1, 2, 4, 8 or 16, got: %u", info->bits_per_channel);
            break;
        case 3:
            if(info->bits_per_channel !=1 && info->bits_per_channel !=2 && info->bits_per_channel !=4 && info->bits_per_channel !=8)
                IM_ERR("Invalid bit depth for color type 3. Expected 1, 2, 4 or 8, got: %u", info->bits_per_channel);
            break;
        case 2:
        case 4:
        case 6:
            if(info->bits_per_channel != 8 && info->bits_per_channel != 16)
                IM_ERR("Invalid bit depth for color type 6. Expected 8 or 16, got: %u", info->bits_per_channel);
            break;
    }
    if(info->compression_method != 0)
        IM_ERR("Compression method is supposed to be 0, but it's: %u.", info->compression_method);
    if(info->filter_method != 0)
        IM_ERR("Filter method is supposed to be 0, but it's %u.", info->filter_method);
    if(info->interlace_method != 0 && info->interlace_method != 1)
        IM_ERR("Interlace method is supposed to be 0 or 1, but it's %u.", info->interlace_method);
#endif

    printf("width: %d\n", info->width);
    printf("height: %d\n", info->height);
    printf("bits_per_channel: %d\n", info->bits_per_channel);
    printf("color_type: %d\n", info->color_type);
    printf("compression_method: %d\n", info->compression_method);
    printf("filter_method: %d\n", info->filter_method);
    printf("interlace_method: %d\n", info->interlace_method);

    switch(info->color_type) {
        case RGB:
            info->channel_count = 3;
            break;
        case RGBA:
            info->channel_count = 4;
            break;
        case PALETTE:
            info->channel_count = 0;
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
    uint32_t length = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("gAMA_data_length: %d\n", length);
    if(length != 4u){
        IM_ERR("Length section of gAMA chunk is not 4.");
    }

    char *chunk_type = (char*)consume(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("chunk_type: %.*s\n", PNG_CHUNK_TYPE_LEN, chunk_type);

    uint32_t tmp  = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    info->gamma = tmp / 100000.0;
    printf("gAMA chunk: gamma = %.5f\n", info->gamma);

    uint32_t *crc = (uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
}

void im_png_parse_chunk_cHRM(im_png_info *info) {
    uint32_t length = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("cHRM_data_length: %d\n", length);
    if(length != 32u){
        IM_ERR("Length section of cHRM chunk is not 32.");
    }

    char *chunk_type = (char*)consume(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("chunk_type: %.*s\n", PNG_CHUNK_TYPE_LEN, chunk_type);

    uint32_t tmp;
    tmp = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    info->white_x = tmp / 100000.0;
    tmp = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    info->white_y = tmp / 100000.0;
    tmp = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    info->red_x = tmp / 100000.0;
    tmp = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    info->red_y = tmp / 100000.0;
    tmp = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    info->green_x = tmp / 100000.0;
    tmp = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    info->green_y = tmp / 100000.0;
    tmp = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    info->blue_x = tmp / 100000.0;
    tmp = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    info->blue_y = tmp / 100000.0;
    printf("white_x = %.5f\n", info->white_x);
    printf("white_y = %.5f\n", info->white_y);
    printf("red_x = %.5f\n", info->red_x);
    printf("red_y = %.5f\n", info->red_y);
    printf("green_x = %.5f\n", info->green_x);
    printf("green_y = %.5f\n", info->green_y);
    printf("blue_x = %.5f\n", info->blue_x);
    printf("blue_y = %.5f\n", info->blue_y);

    uint32_t *crc = (uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
}

void im_png_parse_chunk_bKGD(im_png_info *info) {

    uint32_t length = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("bKGD_data_length: %d\n", length);

    char *chunk_type = (char*)consume(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("chunk_type: %.*s\n", PNG_CHUNK_TYPE_LEN, chunk_type);

    switch(info->color_type) {
        case 0:
        case 4: {
            #ifndef IM_NO_ERRORS
            if(length != 2u){
                IM_ERR("For color type %d, data len is supposed to be 2. data_len is: %d.", info->color_type, length);
            }
            #endif
            info->bkgd_gray = *(uint16_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint16_t));
            break;
        }
        case 2:
        case 6: {
            #ifndef IM_NO_ERRORS
            if(length != 6u){
                IM_ERR("For color type %d, data_len is supposed to be 6. data_len is: %d.", info->color_type, length);
            }
            #endif
            info->bkgd_r = *(uint16_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint16_t));
            info->bkgd_g = *(uint16_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint16_t));
            info->bkgd_b = *(uint16_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint16_t));
            break;
        }
        case 3: {
            #ifndef IM_NO_ERRORS
            if(length != 1u){
                IM_ERR("For color type 3, data_len is supposed to be 1. data_len is: %d.", length);
            }
            #endif
            info->bkgd_palette_idx = *(uint8_t*)consume(&info->at, info->end_of_file, sizeof(uint8_t));
            break;
        }
    }


    uint32_t *crc = (uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
}

void im_png_parse_chunk_tIME(im_png_info *info) {

    uint32_t length = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("tIME_data_length: %d\n", length);
    if(length != 7u){
        IM_ERR("Length section of tIME chunk is not 13.");
    }

    char *chunk_type = (char*)consume(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("chunk_type: %.*s\n", PNG_CHUNK_TYPE_LEN, chunk_type);

    info->year = *(uint16_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint16_t));
    info->month = *(uint8_t*)consume(&info->at, info->end_of_file, sizeof(uint8_t));
    info->day = *(uint8_t*)consume(&info->at, info->end_of_file, sizeof(uint8_t));
    info->hour = *(uint8_t*)consume(&info->at, info->end_of_file, sizeof(uint8_t));
    info->minute = *(uint8_t*)consume(&info->at, info->end_of_file, sizeof(uint8_t));
    info->second = *(uint8_t*)consume(&info->at, info->end_of_file, sizeof(uint8_t));

    uint32_t *crc = (uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
}

void im_png_parse_chunk_tEXt(im_png_info *info) {

    uint32_t length = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("tEXT_data_length: %d\n", length);

    char *chunk_type = (char*)consume(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("chunk_type: %.*s\n", PNG_CHUNK_TYPE_LEN, chunk_type);

    char keyword[80] = {0};
    char at = 0;
    int counter = 0;
    do {
        if(counter >= 79) break;
        at = *(char*)consume(&info->at, info->end_of_file, 1);
        keyword[counter++] = at;
    } while(at != '\0');

    size_t text_len = length - counter;
    char *text = (char*)consume(&info->at, info->end_of_file, 1);
    consume(&info->at, info->end_of_file, text_len - 1);

    printf("%s %.*s\n", keyword, text_len, text);

    uint32_t *crc = (uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
}

void im_png_parse_chunk_IEND(im_png_info *info) {

    uint32_t length = *(uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("IEND_data_length: %d\n", length);
    if(length != 0u){
        IM_ERR("Length section of IEND chunk is not 0.");
    }

    char *chunk_type = (char*)consume(&info->at, info->end_of_file, sizeof(uint32_t));
    printf("chunk_type: %.*s\n", PNG_CHUNK_TYPE_LEN, chunk_type);


    uint32_t *crc = (uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));
}

char *get_next_chunk_type(im_png_info *info) {
    if(info->at + PNG_CHUNK_DATA_LEN < info->end_of_file) {
        return info->at + PNG_CHUNK_DATA_LEN;
    } else {
        IM_ERROR("Tried to read png chunk after end of file. Malformed PNG. Not going to load.");
        return NULL;
    }
}

/* Skip the chunk length(4 bytes), chunk type (4 bytes), chunk data, and CRC (4 bytes) */
void skip_chunk(im_png_info *info) {
    uint32_t *length = (uint32_t*)consume_and_endian_swap(&info->at, info->end_of_file, sizeof(uint32_t));

    size_t bytes_needed_to_skip_chunk = PNG_CHUNK_TYPE_LEN + *length + PNG_CHUNK_CRC_LEN;

    /* Advance the offset */
    info->at += bytes_needed_to_skip_chunk;
}

void im_png_peek_bytes(im_png_info *info, void* buf, char *offset, const size_t bytes_to_read) {
    if(offset < info->end_of_file) {
        im_memcpy(buf, offset, bytes_to_read);
    } else {
        fprintf(stderr, "Error: %s(): tried to read bytes past end of file, not going to read.", __func__);
    }
}

char* im_png_peek_next_chunk(im_png_info *info, char *current_chunk) {
    uint32_t data_length = 0;
    im_png_peek_bytes(info, &data_length, current_chunk, PNG_CHUNK_DATA_LEN);
    endian_swap(&data_length);
    printf("DATA LENGTH: %d\n", data_length);

    return current_chunk + PNG_CHUNK_DATA_LEN + PNG_CHUNK_TYPE_LEN + data_length + PNG_CHUNK_CRC_LEN;
}

typedef struct {
    uint8_t *data;
    size_t bitpos; /* bit offset from start */
} im_bitsream;

uint32_t consume_bits(im_bitsream *bs, int n) {
    uint32_t val = 0;
    for (int i = 0; i < n; i++) {
        size_t byte_index = bs->bitpos / 8;
        int bit_index = bs->bitpos % 8;
        val |= ((bs->data[byte_index] >> bit_index) & 1) << i;
        bs->bitpos++;
    }
    return val;
}

void align_next_byte(im_bitsream *bs) {
    size_t bits_out_of_alignment = bs->bitpos & 7;
    if(bits_out_of_alignment) {
        consume_bits(bs, 8 - bits_out_of_alignment);
    }
}

void im_memset(void *buffer, int value, size_t count) {
    unsigned char *buf = buffer;
    for(size_t i = 0; i < count; i++) {
        buf[i] = value;
    }
}


typedef struct {
    int len;
    int code;
}huffman_tree;

#define FIXED_LITERAL_COUNT 288
#define FIXED_DISTANCE_COUNT 32
huffman_tree literal_length_tree[FIXED_LITERAL_COUNT];
huffman_tree distance_tree[FIXED_DISTANCE_COUNT];

void im_png_build_fixed_huffman_tree() {
    static const uint8_t fixed_literal_length_code_lengths[FIXED_LITERAL_COUNT] = {
        /* literal values are from 0 to 255 */
        /* 0 ... 143 = 144 */
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        /* 144 ... 255 = 112 */
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        /* length values are from 257 to 285 (256 signifies end of block)*/
        /* 256 - 279 */
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        /* 280 - 287 */
        8, 8, 8, 8, 8, 8, 8, 8
    };

    static const uint8_t fixed_distance_code_lengths[FIXED_DISTANCE_COUNT] = {
        5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 5,
    };

    #define MAX_BITS 9 /* dynamic huffman would use 15 bits, we are just using 9 here because it's big enough for the fixed lengths */
    int code, bits;
    int next_code[MAX_BITS + 1] = {0};
    int bl_count[MAX_BITS + 1];

    /* literal-length tree generation */
    bl_count[0] = 0;
    bl_count[1] = 0;
    bl_count[2] = 0;
    bl_count[3] = 0;
    bl_count[4] = 0;
    bl_count[5] = 0;
    bl_count[6] = 0;
    bl_count[7] = 24;
    bl_count[8] = 152;
    bl_count[9] = 112;

    for (bits = 1, code = 0; bits <= MAX_BITS; bits++) {
        code = (code + bl_count[bits-1]) << 1;
        next_code[bits] = code;
    }

    for (int n = 0; n < FIXED_LITERAL_COUNT; n++) {
        int len = fixed_literal_length_code_lengths[n];
        literal_length_tree[n].len = len;

        if (len != 0) {
            literal_length_tree[n].code = next_code[len]++;
        } else {
            literal_length_tree[n].code = 0;
        }

    }

    /* distance tree generation */
    bl_count[0] = 0;
    bl_count[1] = 0;
    bl_count[2] = 0;
    bl_count[3] = 0;
    bl_count[4] = 0;
    bl_count[5] = 32;
    bl_count[6] = 0;
    bl_count[7] = 0;
    bl_count[8] = 0;
    bl_count[9] = 0;

    for (bits = 1, code = 0; bits <= MAX_BITS; bits++) {
        code = (code + bl_count[bits-1]) << 1;
        next_code[bits] = code;
    }

    for (int n = 0; n < FIXED_DISTANCE_COUNT; n++) {
        int len = fixed_distance_code_lengths[n];
        distance_tree[n].len = len;

        if (len != 0) {
            distance_tree[n].code = next_code[len]++;
        } else {
            distance_tree[n].code = 0;
        }

    }

}

// Paeth predictor function for filter type 4
static uint8_t paeth_predictor(uint8_t a, uint8_t b, uint8_t c) {
    int p = a + b - c;
    int pa = abs(p - a);
    int pb = abs(p - b);
    int pc = abs(p - c);
    
    if (pa <= pb && pa <= pc) return a;
    else if (pb <= pc) return b;
    else return c;
}

// Unfilter the decompressed image data
static void im_png_unfilter(im_png_info *info) {
    size_t bytes_per_pixel = (info->bits_per_channel * info->channel_count + 7) / 8;
    size_t bytes_per_scanline = (info->width * info->channel_count * info->bits_per_channel + 7) / 8;
    size_t stride = bytes_per_scanline + 1; // +1 for filter byte
    
    printf("Unfiltering: bytes_per_pixel=%zu, bytes_per_scanline=%zu\n", bytes_per_pixel, bytes_per_scanline);
    
    for (size_t y = 0; y < info->height; y++) {
        size_t scanline_offset = y * stride;
        uint8_t filter_type = info->png_pixels[scanline_offset];
        uint8_t *scanline = (uint8_t*)info->png_pixels + scanline_offset + 1;
        uint8_t *prev_scanline = (y > 0) ? (uint8_t*)info->png_pixels + (y - 1) * stride + 1 : NULL;
        
        switch (filter_type) {
            case 0: // None
                break;
                
            case 1: // Sub
                for (size_t x = bytes_per_pixel; x < bytes_per_scanline; x++) {
                    scanline[x] = (scanline[x] + scanline[x - bytes_per_pixel]) & 0xFF;
                }
                break;
                
            case 2: // Up
                if (prev_scanline) {
                    for (size_t x = 0; x < bytes_per_scanline; x++) {
                        scanline[x] = (scanline[x] + prev_scanline[x]) & 0xFF;
                    }
                }
                break;
                
            case 3: // Average
                for (size_t x = 0; x < bytes_per_scanline; x++) {
                    uint8_t left = (x >= bytes_per_pixel) ? scanline[x - bytes_per_pixel] : 0;
                    uint8_t up = prev_scanline ? prev_scanline[x] : 0;
                    scanline[x] = (scanline[x] + ((left + up) / 2)) & 0xFF;
                }
                break;
                
            case 4: // Paeth
                for (size_t x = 0; x < bytes_per_scanline; x++) {
                    uint8_t left = (x >= bytes_per_pixel) ? scanline[x - bytes_per_pixel] : 0;
                    uint8_t up = prev_scanline ? prev_scanline[x] : 0;
                    uint8_t up_left = (prev_scanline && x >= bytes_per_pixel) ? prev_scanline[x - bytes_per_pixel] : 0;
                    scanline[x] = (scanline[x] + paeth_predictor(left, up, up_left)) & 0xFF;
                }
                break;
                
            default:
                IM_ERR("Unknown filter type: %d", filter_type);
                break;
        }
    }
    
    // Now remove the filter bytes and compact the data
    char *unfiltered = malloc(info->height * bytes_per_scanline);
    if (!unfiltered) {
        IM_ERR("Failed to allocate memory for unfiltered data");
        return;
    }
    
    for (size_t y = 0; y < info->height; y++) {
        size_t src_offset = y * stride + 1; // +1 to skip filter byte
        size_t dst_offset = y * bytes_per_scanline;
        im_memcpy(unfiltered + dst_offset, info->png_pixels + src_offset, bytes_per_scanline);
    }
    
    free(info->png_pixels);
    info->png_pixels = unfiltered;
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

// Decode a symbol from fixed Huffman literal/length tree
int decode_fixed_literal_length(im_bitsream *bs) {
    uint32_t code = 0;
    
    // Read 7 bits first
    for (int i = 0; i < 7; i++) {
        code |= consume_bits(bs, 1) << i;
    }
    
    // Check for 7-bit codes (256-279)
    if (code <= 23) {
        return code + 256;
    }
    
    // Read 8th bit
    code |= consume_bits(bs, 1) << 7;
    
    // Check for 8-bit codes (0-143 and 280-287)
    if (code >= 0x30 && code <= 0xBF) {
        return code - 0x30; // Codes 48-191 map to symbols 0-143
    }
    if (code >= 0xC0 && code <= 0xC7) {
        return code - 0xC0 + 280; // Codes 192-199 map to symbols 280-287
    }
    
    // Read 9th bit
    code |= consume_bits(bs, 1) << 8;
    
    // Check for 9-bit codes (144-255)
    if (code >= 0x190 && code <= 0x1FF) {
        return code - 0x190 + 144; // Codes 400-511 map to symbols 144-255
    }
    
    return -1; // Error
}

// Decode a distance code from fixed Huffman distance tree
int decode_fixed_distance(im_bitsream *bs) {
    // All distance codes are 5 bits in fixed Huffman
    uint32_t code = 0;
    for (int i = 0; i < 5; i++) {
        code = (code << 1) | consume_bits(bs, 1);
    }
    
    // Reverse the bits (Huffman codes are read LSB first)
    uint32_t reversed = 0;
    for (int i = 0; i < 5; i++) {
        reversed = (reversed << 1) | ((code >> i) & 1);
    }
    
    return reversed;
}


void build_huffman_tree(huffman_tree *tree, uint8_t *lengths, int count) {
    int bl_count[16] = {0};
    int next_code[16] = {0};
    
    // Count code lengths
    for (int i = 0; i < count; i++) {
        if (lengths[i] < 16) {
            bl_count[lengths[i]]++;
        }
    }
    
    bl_count[0] = 0; // Codes with length 0 are not used
    
    // Generate starting code for each length (canonical Huffman algorithm)
    int code = 0;
    for (int bits = 1; bits < 16; bits++) {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }
    
    // Assign codes to symbols
    for (int n = 0; n < count; n++) {
        int len = lengths[n];
        if (len != 0) {
            tree[n].len = len;
            tree[n].code = next_code[len];
            next_code[len]++;
        } else {
            tree[n].len = 0;
            tree[n].code = 0;
        }
    }
}


int decode_symbol(im_bitsream *bs, huffman_tree *tree, int max_symbols) {
    uint32_t code = 0;
    size_t start_pos = bs->bitpos;
    
    for (int bits = 1; bits <= 15; bits++) {
        // Read one bit (LSB-first from stream)
        code |= consume_bits(bs, 1) << (bits - 1);
        
        // Reverse the code we've read to match canonical (MSB-first) order
        uint32_t reversed_code = 0;
        for (int b = 0; b < bits; b++) {
            reversed_code |= ((code >> b) & 1) << (bits - 1 - b);
        }
        
        // Try to match against all symbols of this bit length
        for (int i = 0; i < max_symbols; i++) {
            if (tree[i].len == bits && tree[i].code == reversed_code) {
                return i;
            }
        }
    }
    
    // Failed to decode - print debug info
    printf("Failed to decode symbol starting at bit %zu, final code read: 0x%X\n", start_pos, code);
    return -1;
}

char *im_png_decompress(im_png_info *info, char *current_IDAT_chunk, size_t *idat_chunk_count) {

    uint32_t comp_data_size = 0;
    uint32_t tmp = 0;

    char *start = current_IDAT_chunk;

    /* find the total size of the compressed data */
    while(*(uint32_t*)(current_IDAT_chunk + PNG_CHUNK_DATA_LEN) == CHUNK_IDAT) {

        im_memcpy(&tmp, current_IDAT_chunk, PNG_CHUNK_DATA_LEN);
        endian_swap(&tmp);
        printf(" THE FUCKING DATA LENGTH: %d\n", tmp);

        comp_data_size += tmp;
        current_IDAT_chunk = im_png_peek_next_chunk(info, current_IDAT_chunk);
        printf("TOTAL SIZE OF COMPRESSED DATA: %d\n", comp_data_size);
        (*idat_chunk_count)++;
    }

    char *compressed_data = (char*)malloc(comp_data_size);
    if (!compressed_data) return NULL;

    size_t offset = 0;
    uint32_t current_chunk_data_len = 0;

    /* concatenate the data sections of all the IDAT chunks together. */
    /* we need to do this in order to decompress the data. */
    current_IDAT_chunk = start;
    while (*(uint32_t*)(current_IDAT_chunk + 4) == CHUNK_IDAT) {
        im_memcpy(&current_chunk_data_len, current_IDAT_chunk, PNG_CHUNK_DATA_LEN);
        endian_swap(&current_chunk_data_len);

        im_memcpy(compressed_data + offset, current_IDAT_chunk + PNG_CHUNK_DATA_LEN + PNG_CHUNK_TYPE_LEN, current_chunk_data_len);
        offset += current_chunk_data_len;

        current_IDAT_chunk += PNG_CHUNK_DATA_LEN + PNG_CHUNK_TYPE_LEN + current_chunk_data_len + PNG_CHUNK_CRC_LEN;
    }

    /* this contains the compression method in the lower nibble, and the compression window size in the higher nibble. */
    char *zlib_header = compressed_data;
    compressed_data += 2; /* skip zlib header. */
    uint8_t cmf = zlib_header[0];
    uint8_t comp_method = cmf & 0x0F;   /* bits 0 - 3 | HAS TO BE 8 BECAUSE .PNG SPEC ONLY SUPPORTS DEFLATE. */
    uint8_t window_size_bits  = (cmf >> 4) & 0x0F; /* bit 4 - 8 */
    uint8_t window_size = 1 << (window_size_bits + 8); /* window = 1 << (8 + bits) | HAS to be 2^16 */

    uint8_t flg = zlib_header[1];
    uint8_t check_bits = flg & 0x1F;         /* bits 0-4 | Used for integrity check */
    uint8_t preset_dict_flag = (flg >> 5) & 1;  /* bit 5 | HAS TO BE 0 BECAUSE .PNG SPEC SAID SO. */
    uint8_t compression_level = (flg >> 6) & 3; /* bits 6-7 | 0 - 3 Compression level hints. These don't matter when decompressing. */

    printf("Compression method: %d (should be 8 = DEFLATE)\n", comp_method);
    printf("Compression window size: %d KB\n", window_size);
    printf("check_bits: %d\n", check_bits);
    printf("preset_dict_flag: %d\n", preset_dict_flag);
    printf("Compression level: %d\n", compression_level);

    printf("%lu\n", sizeof(cmf + flg));

    if (((cmf << 8) + flg) % 31 == 0) {
        printf("Info: Integrity check successful!\ndecompressing...\n");
        size_t bytes_per_scanline = im_ceil(info->width * info->channel_count * info->bits_per_channel, 8);
        size_t image_size_after_decompression = info->height * (bytes_per_scanline + 1); /* +1 per scanline for filter byte */
        info->png_pixels = malloc(image_size_after_decompression);
        struct {
            uint8_t BFINAL;
            uint8_t BTYPE;
        }block_header;
        size_t offset = 0;
        im_bitsream bs = { (uint8_t*)compressed_data, 0 };
        do {
            block_header.BFINAL = consume_bits(&bs, 1);
            block_header.BTYPE = consume_bits(&bs, 2);
            printf("block_type %d, is_last_block %d\n", block_header.BTYPE, block_header.BFINAL);
            switch(block_header.BTYPE) {
                case UNCOMPRESSED: {
                    IM_INFO("Copying uncompressed block!\n");
                    align_next_byte(&bs);
                    // since uncompressed data size can range between 0 and 65535 bytes,
                    // len has to bigger than or equal to 0 and less than or equal to 65,535 bytes.
                    uint16_t len  = consume_bits(&bs, 16);
                    uint16_t nlen = consume_bits(&bs, 16);

                    if ((len ^ nlen) != 0xFFFF) {
                        IM_ERR("Corrupted block! Png is malformed. Not going to load png.\n");
                        return NULL;
                    }
                    for (uint16_t i = 0; i < len; i++) {
                        info->png_pixels[offset++] = (uint8_t)consume_bits(&bs, 8);
                    }
                    break;
                }
                case FIXED_HUFFMAN: {
                    IM_INFO("Decompressing fixed huffman block!");
                    im_png_build_fixed_huffman_tree();

                    while (1) {
                        int symbol = decode_fixed_literal_length(&bs);

                        if (symbol < 0) {
                            IM_ERR("Failed to decode symbol");
                            break;
                        }

                        if (symbol < 256) {
                            // Literal byte - copy to output
                            info->png_pixels[offset++] = (uint8_t)symbol;
                        } else if (symbol == 256) {
                            // End of block
                            break;
                        } else if (symbol >= 257 && symbol <= 285) {
                            // Length/distance pair
                            int length_code = symbol - 257;
                            int length = length_base[length_code];

                            // Read extra length bits if needed
                            if (length_extra[length_code] > 0) {
                                length += consume_bits(&bs, length_extra[length_code]);
                            }

                            // Decode distance
                            int dist_code = decode_fixed_distance(&bs);
                            int distance = distance_base[dist_code];

                            // Read extra distance bits if needed
                            if (distance_extra[dist_code] > 0) {
                                distance += consume_bits(&bs, distance_extra[dist_code]);
                            }

                            // Copy previous bytes
                            for (int i = 0; i < length; i++) {
                                info->png_pixels[offset] = info->png_pixels[offset - distance];
                                offset++;
                            }
                        }
                    }
                    break;
                }
                case DYNAMIC_HUFFMAN: {
                    IM_INFO("Decompressing dynamic huffman block!");
                    
                    uint16_t HLIT  = consume_bits(&bs, 5) + 257;  // # of literal/length codes
                    uint16_t HDIST = consume_bits(&bs, 5) + 1;    // # of distance codes
                    uint16_t HCLEN = consume_bits(&bs, 4) + 4;    // # of code length codes
                    
                    //printf("HLIT=%d, HDIST=%d, HCLEN=%d\n", HLIT, HDIST, HCLEN);
                    
                    static const int code_length_order[19] = {
                        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
                    };
                    
                    uint8_t code_length_lengths[19] = {0};
                    
                    // Read code length code lengths
                    for (int i = 0; i < HCLEN; i++) {
                        code_length_lengths[code_length_order[i]] = consume_bits(&bs, 3);
                    }
                    
                    // Build code length tree
                    huffman_tree code_length_tree[19];
                    build_huffman_tree(code_length_tree, code_length_lengths, 19);
                    
                    // Debug: print code length tree
                    //printf("Code length tree:\n");
                    for (int i = 0; i < 19; i++) {
                        if (code_length_tree[i].len > 0) {
                            //printf("  Symbol %d: len=%d, code=%d\n", i, code_length_tree[i].len, code_length_tree[i].code);
                        }
                    }
                    
                    // Decode literal/length and distance code lengths
                    uint8_t *lengths = malloc((HLIT + HDIST) * sizeof(uint8_t));
                    if (!lengths) {
                        IM_ERR("Failed to allocate memory for code lengths");
                        break;
                    }
                    im_memset(lengths, 0, HLIT + HDIST);
                    
                    int i = 0;
                    while (i < HLIT + HDIST) {
                        int symbol = decode_symbol(&bs, code_length_tree, 19);
                        
                        if (symbol < 0) {
                            IM_ERR("Failed to decode code length symbol at position %d, bitpos=%zu", i, bs.bitpos);
                            free(lengths);
                            break;
                        }
                        
                        //printf("Decoded symbol %d at position %d\n", symbol, i);
                        
                        if (symbol < 16) {
                            // Literal length
                            lengths[i++] = symbol;
                        } else if (symbol == 16) {
                            // Repeat previous code length 3-6 times
                            if (i == 0) {
                                IM_ERR("Cannot repeat previous code - no previous code exists");
                                free(lengths);
                                break;
                            }
                            int repeat = consume_bits(&bs, 2) + 3;
                            uint8_t prev = lengths[i - 1];
                            for (int j = 0; j < repeat && i < HLIT + HDIST; j++) {
                                lengths[i++] = prev;
                            }
                        } else if (symbol == 17) {
                            // Repeat 0 for 3-10 times
                            int repeat = consume_bits(&bs, 3) + 3;
                            for (int j = 0; j < repeat && i < HLIT + HDIST; j++) {
                                lengths[i++] = 0;
                            }
                        } else if (symbol == 18) {
                            // Repeat 0 for 11-138 times
                            int repeat = consume_bits(&bs, 7) + 11;
                            for (int j = 0; j < repeat && i < HLIT + HDIST; j++) {
                                lengths[i++] = 0;
                            }
                        }
                    }
                    
                    if (i < HLIT + HDIST) {
                        IM_ERR("Failed to decode all code lengths (got %d, expected %d)", i, HLIT + HDIST);
                        // lengths already freed above
                        break;
                    }
                    
                    // Build literal/length and distance trees
                    huffman_tree *dyn_literal_tree = malloc(HLIT * sizeof(huffman_tree));
                    huffman_tree *dyn_distance_tree = malloc(HDIST * sizeof(huffman_tree));
                    
                    if (!dyn_literal_tree || !dyn_distance_tree) {
                        IM_ERR("Failed to allocate Huffman trees");
                        if (dyn_literal_tree) free(dyn_literal_tree);
                        if (dyn_distance_tree) free(dyn_distance_tree);
                        free(lengths);
                        break;
                    }
                    
                    build_huffman_tree(dyn_literal_tree, lengths, HLIT);
                    build_huffman_tree(dyn_distance_tree, lengths + HLIT, HDIST);
                    
                    // Decode compressed data
                    while (1) {
                        if (offset >= image_size_after_decompression) {
                            IM_INFO("Reached end of output buffer");
                            break;
                        }
                        
                        int symbol = decode_symbol(&bs, dyn_literal_tree, HLIT);
                        
                        if (symbol < 0) {
                            IM_ERR("Failed to decode symbol");
                            break;
                        }
                        
                        if (symbol < 256) {
                            // Literal byte
                            info->png_pixels[offset++] = (uint8_t)symbol;
                        } else if (symbol == 256) {
                            // End of block
                            IM_INFO("End of block marker found");
                            break;
                        } else if (symbol >= 257 && symbol <= 285) {
                            // Length/distance pair
                            int length_code = symbol - 257;
                            int length = length_base[length_code];
                            
                            if (length_extra[length_code] > 0) {
                                length += consume_bits(&bs, length_extra[length_code]);
                            }
                            
                            int dist_symbol = decode_symbol(&bs, dyn_distance_tree, HDIST);
                            if (dist_symbol < 0 || dist_symbol >= 30) {
                                IM_ERR("Invalid distance symbol: %d", dist_symbol);
                                break;
                            }
                            
                            int distance = distance_base[dist_symbol];
                            
                            if (distance_extra[dist_symbol] > 0) {
                                distance += consume_bits(&bs, distance_extra[dist_symbol]);
                            }
                            
                            if (distance > offset) {
                                IM_ERR("Distance %d exceeds current offset %zu", distance, offset);
                                break;
                            }
                            
                            if (offset + length > image_size_after_decompression) {
                                IM_ERR("Length/distance pair would overflow buffer");
                                break;
                            }
                            
                            // Copy previous bytes
                            for (int i = 0; i < length; i++) {
                                info->png_pixels[offset] = info->png_pixels[offset - distance];
                                offset++;
                            }
                        }
                    }
                    
                    free(dyn_literal_tree);
                    free(dyn_distance_tree);
                    free(lengths);
                    break;
                }
                case RESERVED: {
                    IM_ERR("Encountered reserved (invalid) block type!\n");
                    break;
                }
            }
        } while(!block_header.BFINAL);

    } else {
        fprintf(stderr, "Error: Integrity check failed.\n");
    }

    im_png_unfilter(info);
    return info->png_pixels;
}

typedef struct {
    uint32_t length;
    uint32_t type;
}im_png_header;

typedef struct {
    uint32_t crc;
}im_png_footer;

unsigned char *im_png_load(char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {

    im_png_info info = {0};
    info.first_ihdr = im_true;
    info.png_file = image_file;
    info.at = image_file;

    info.end_of_file = image_file + file_size;
    char *png_sig = (char*)consume(&info.at, info.end_of_file, sizeof(png_sig));
    im_png_print_bytes(png_sig, PNG_SIG_LEN);

    char *next_chunk_type = NULL;
    next_chunk_type = get_next_chunk_type(&info);
    if(!next_chunk_type) return NULL;

    while(*(uint32_t*)next_chunk_type != CHUNK_IEND) {
        next_chunk_type = get_next_chunk_type(&info);
        if(!next_chunk_type) return NULL;
        printf("chunk: %.*s\n", 4, next_chunk_type);
        switch(*(uint32_t*)next_chunk_type)  {
            case CHUNK_IHDR:
                im_png_parse_chunk_IHDR(&info);
                *width = info.width;
                *height = info.height;
                *num_channels = info.channel_count;
                printf("-----------------------------\n");
                break;
            case CHUNK_cHRM:
                im_png_parse_chunk_cHRM(&info);
                printf("-----------------------------\n");
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
                skip_chunk(&info);
                break;
            case CHUNK_bKGD:
                im_png_parse_chunk_bKGD(&info);
                printf("-----------------------------\n");
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
                size_t idat_chunk_count = 0;
                char *err = im_png_decompress(&info, next_chunk_type - PNG_CHUNK_DATA_LEN, &idat_chunk_count);
                if(!err) return NULL;
                for(int i = 0; i < idat_chunk_count; i++) {
                    skip_chunk(&info);
                }
                printf("-----------------------------\n");
                break;
            }
            case CHUNK_iTXt:
                skip_chunk(&info);
                break;
            case CHUNK_tEXt:
                im_png_parse_chunk_tEXt(&info);
                printf("-----------------------------\n");
                break;
            case CHUNK_zTXt:
                skip_chunk(&info);
                break;
            case CHUNK_tIME:
                im_png_parse_chunk_tIME(&info);
                printf("-----------------------------\n");
                break;
            case CHUNK_gAMA:
                im_png_parse_chunk_gAMA(&info);
                printf("-----------------------------\n");
                break;
            case CHUNK_IEND:
                im_png_parse_chunk_IEND(&info);
                printf("-----------------------------\n");
                break;
            default:
                skip_chunk(&info);
                break;
        }
    }
    return info.png_pixels;
}

static char consume_byte(char **at, char *end_of_file) {
    char *orig = *at;
    if(*at < end_of_file) {
        *at += 1;
        return *orig;
    }
    fprintf(stderr, "Error: %s(), will not read past end of file.\n", __func__);
    return 0;  // Return 0 on error, which will stop the while loop
}

/* peeks the current byte without consuming it */
static char peek_byte(char *current_pos, char *end_of_file) {
    if (current_pos < end_of_file) {
        return *current_pos;
    }
    fprintf(stderr, "Error: %s(), will not peek past end of file.", __func__);
    return *current_pos;
}

im_bool is_end_of_line(char ch) {
    return ch == '\n' || ch == '\r';
}

char *im_parse_pnm_ascii_header(char *at, char *end_of_file, int *width, int *height) {

    /* skip sig */
    char *sig = consume(&at, end_of_file, 2);

    /* eat whitespaces after sig */
    char c = 0;
    while ((c = peek_byte(at, end_of_file)) && (c == ' ' || c == '\n' || c == '\r' || c == '\t')) {
        consume_byte(&at, end_of_file);
    }

    /* eat comments after whitespaces*/

    while(*at == '#') {
        if(peek_byte(at, end_of_file) == '#') {
            char byte = 0;
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

unsigned char *im_p1_load(char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    char *at = image_file;
    char *end_of_file = image_file + file_size;
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
    char c = 0;

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

int get_max_val(char **at, char *end_of_file) {
    int max_val = 0;
    char c = peek_byte(*at, end_of_file);

    if (c >= '0' && c <= '9') {
        while ((c = peek_byte(*at, end_of_file)) >= '0' && c <= '9') {
            max_val = max_val * 10 + (c - '0');
            consume_byte(at, end_of_file);
        }
        return max_val;
    }

    return -1; // Error: no valid number found
}

unsigned char *im_p2_load(char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    char *at = image_file;
    char *end_of_file = image_file + file_size;
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
    char c;
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

unsigned char *im_p3_load(char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    char *at = image_file;
    char *end_of_file = image_file + file_size;
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
    char c;
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

unsigned char *im_p4_load(char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    char *at = image_file;
    char *end_of_file = image_file + file_size;
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

unsigned char *im_p5_load(char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    char *at = image_file;
    char *end_of_file = image_file + file_size;
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
    char c = peek_byte(at, end_of_file);
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

unsigned char *im_p6_load(char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    char *at = image_file;
    char *end_of_file = image_file + file_size;
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
    char c = peek_byte(at, end_of_file);
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

unsigned char *im_psd_load(char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    char *at = image_file;
    char *end_of_file = image_file + file_size;
    char *sig = consume(&at, end_of_file, 4);
    printf("psd_sig: %.*s\n", 4, sig);
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

size_t load_bmp_start(char **at, char *end_of_file, int *width, int *height) {
    bitmap_header_os2_16 *header;
    header = (bitmap_header_os2_16*)consume(at, end_of_file, sizeof(bitmap_header_os2_16));
    *width = header->width;
    *height = header->height;
    if(header->num_planes != 1) {
        IM_ERR("Expected num_planes to be 1, but it's not. We will assume that the rest of the file is not corrupted.");
    }

    size_t bits_per_pixel = 0;

    switch(header->bit_count) {
        case BMP_BITCOUNT_SPECIFIED_BY_PNG_OR_JPEG:
            break;

        case BMP_BITCOUNT_MONOCHROME:
            bits_per_pixel = 1;
            break;

        case BMP_BITCOUNT_16_COLOR_PALETTE:
            bits_per_pixel = 4;
            break;

        case BMP_BITCOUNT_256_COLOR_PALETTE:
            bits_per_pixel = 8;
            break;

        case BMP_BITCOUNT_RGB_16: /* five bits for red, five for green and five for blue. Last bit is not used */
            bits_per_pixel = 5;
            break;

        case BMP_BITCOUNT_RGB_24:
            bits_per_pixel = 8;
            break;

        case BMP_BITCOUNT_RGB_32:
            bits_per_pixel = 8; /* The high byte is reserved (for god knows what).*/
            break;
    }
    return bits_per_pixel;
}

unsigned char *im_bmp_load(char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {
    char *at = image_file;
    char *end_of_file = image_file + file_size;

    bitmap_file_header file_header;
    file_header.type = *(uint16_t*)consume(&at, end_of_file, (sizeof(uint16_t)));
    file_header.size = *(uint32_t*)consume(&at, end_of_file, (sizeof(uint32_t)));
    file_header.reserved1 = *(uint16_t*)consume(&at, end_of_file, sizeof(uint16_t));
    file_header.reserved2 = *(uint16_t*)consume(&at, end_of_file, sizeof(uint16_t));
    file_header.bitmap_offset = *(uint32_t*)consume(&at, end_of_file, sizeof(uint32_t));

    if(file_header.size != (uint32_t)file_size) {
        IM_ERR("File size mentioned in bitmap header does not match the file size that we got from windows.\nWe will assume that the rest of the file is not corrupted.");
    }
    if(file_header.reserved1 != 0) {
        IM_ERR("Reserved byte expected to be 0, but is not 0. We will assume that the rest of the file is not corrupted.");
    }
    if(file_header.reserved2 != 0) {
        IM_ERR("Reserved byte expected to be 0, but is not 0. We will assume that the rest of the file is not corrupted.");
    }
    /* Because this file format got multiple revisions, we will just refer to the header
       that comes after the BITMAPFILEHEADER as the "dib_header". */

    if(file_header.bitmap_offset < (uint32_t)sizeof(bitmap_file_header)) {
        IM_ERR("Offset is an unreasonably small number. Corrupt .bmp. Not going to decode.");
        return NULL;
    } else {
        printf("size of file_header: %zu\n", sizeof(bitmap_file_header));
        printf("Offset from start of header: %d\n", file_header.bitmap_offset);
    }

    uint32_t *dib_header_size = (uint32_t*)at; /* this is jank, and unsafe. We should have a peek funciton */

    switch(*dib_header_size) {
        /* the reason why we can't use load_bmp_start on the first case
           is that the width and the height fields in bitmap_header_core
           are different in size to the width and height fields of
           the other header types. uint16_t vs uint32_t
       */
        case BMP_HEADER_TYPE_CORE: {
            bitmap_header_core header;
            header = *(bitmap_header_core*)consume(&at, end_of_file, sizeof(bitmap_header_core));
            *width = header.width;
            *height = header.height;

            size_t bits_per_pixel = 0;
            switch(header.bit_count) { /* this value can only be 1, 4, 8 or 24 in a bitmap_header_core */
                case BMP_BITCOUNT_SPECIFIED_BY_PNG_OR_JPEG:
                    /* BMP_HEADER_TYPE_CORE does not support compression.*/
                    IM_ERR("Could not get the number of bits per pixel in image.\nMalformed .bmp. Not going to load");
                    bits_per_pixel = 0; /* The high byte is reserved (for god knows what).*/
                    return NULL;
                    break;

                case BMP_BITCOUNT_MONOCHROME:
                    bits_per_pixel = 1;
                    break;

                case BMP_BITCOUNT_16_COLOR_PALETTE:
                    bits_per_pixel = 4;
                    break;

                case BMP_BITCOUNT_256_COLOR_PALETTE:
                    bits_per_pixel = 8;
                    break;

                case BMP_BITCOUNT_RGB_16: /* five bits for red, five for green and five for blue. Last bit is not used */
                    IM_ERR("Could not get the number of bits per pixel in image.\nMalformed .bmp. Not going to load");
                    bits_per_pixel = 0; /* The high byte is reserved (for god knows what).*/
                    return NULL;
                    break;

                case BMP_BITCOUNT_RGB_24:
                    bits_per_pixel = 24;
                    break;

                case BMP_BITCOUNT_RGB_32:
                    IM_ERR("Could not get the number of bits per pixel in image.\nMalformed .bmp. Not going to load");
                    bits_per_pixel = 0; /* The high byte is reserved (for god knows what).*/
                    return NULL;
                    break;
            }
            unsigned char *pixel_offset = image_file + file_header.bitmap_offset;

            size_t bytes_per_pixel = bits_per_pixel / 8; /* will be 3 for 24-bpp */
            size_t data_per_row = header.width * bytes_per_pixel;

            /* stride: row size rounded up to 4-byte boundary */
            size_t stride = ((data_per_row + 3) / 4) * 4;
            size_t padding = stride - data_per_row;

            size_t total_bytes = stride * header.height;

            unsigned char *output_pixels = malloc(header.width * header.height * bytes_per_pixel);
            if (!output_pixels) return NULL;

            unsigned char *in = pixel_offset;
            unsigned char *out = output_pixels;

            for (int row = 0; row < header.height; ++row) {
                /* WORKING TOP-DOWN: if BMP is bottom-up, you'd read rows in reverse order */
                memcpy(out, in, data_per_row);
                in  += stride;
                out += data_per_row;
            }
            return out;
            break;

        }
        case BMP_HEADER_TYPE_OS2_16: {
            size_t bits_per_pixel = load_bmp_start(&at, end_of_file, width, height);
            size_t row_size = ((bits_per_pixel * (*width) + 31) / 32) * 4;
            break;
        }
        case BMP_HEADER_TYPE_V1: {
            size_t bits_per_pixel = load_bmp_start(&at, end_of_file, width, height);
            size_t row_size = ((bits_per_pixel * (*width) + 31) / 32) * 4;
            uint32_t *compression_format = (uint32_t*)consume(&at, end_of_file, sizeof(uint32_t));
            break;
        }
        case BMP_HEADER_TYPE_V2: {
            size_t bits_per_pixel = load_bmp_start(&at, end_of_file, width, height);
            size_t row_size = ((bits_per_pixel * (*width) + 31) / 32) * 4;
            uint32_t *compression_format = (uint32_t*)consume(&at, end_of_file, sizeof(uint32_t));
            break;
        }
        case BMP_HEADER_TYPE_V3: {
            size_t bits_per_pixel = load_bmp_start(&at, end_of_file, width, height);
            size_t row_size = ((bits_per_pixel * (*width) + 31) / 32) * 4;
            uint32_t *compression_format = (uint32_t*)consume(&at, end_of_file, sizeof(uint32_t));
            break;
        }
        case BMP_HEADER_TYPE_OS2_64: {
            size_t bits_per_pixel = load_bmp_start(&at, end_of_file, width, height);
            size_t row_size = ((bits_per_pixel * (*width) + 31) / 32) * 4;
            uint32_t *compression_format = (uint32_t*)consume(&at, end_of_file, sizeof(uint32_t));
            break;
        }
        case BMP_HEADER_TYPE_V4: {
            size_t bits_per_pixel = load_bmp_start(&at, end_of_file, width, height);
            size_t row_size = ((bits_per_pixel * (*width) + 31) / 32) * 4;
            uint32_t *compression_format = (uint32_t*)consume(&at, end_of_file, sizeof(uint32_t));
            break;
        }
        case BMP_HEADER_TYPE_V5: {
            size_t bits_per_pixel = load_bmp_start(&at, end_of_file, width, height);
            size_t row_size = ((bits_per_pixel * (*width) + 31) / 32) * 4;
            uint32_t *compression_format = (uint32_t*)consume(&at, end_of_file, sizeof(uint32_t));
            break;
        }
    }

    return NULL;
}

IM_API unsigned char *im_load(const char *image_path, int *width, int *height, int *number_of_channels, int desired_channels) {

    size_t file_size = 0;
    char *image_file = im__read_entire_file(image_path, &file_size);

    if(!image_file) {
        fprintf(stderr, "ERROR: Failed to read image file from disk.\n");
        return NULL;
    }

    if(!file_size) {
        fprintf(stderr, "ERROR: size of image file is 0.\n");
        return NULL;
    }

    uint8_t file_sig[8] = {0};
    char *at = image_file;
    char *end_of_file = image_file + file_size;

    for(int i = 0; i < 8; i++) {
        if(at < end_of_file) {
            im_memcpy(file_sig + i, at++, 1);
        } else {
            break;
        }
    }

    if(im_memcmp(im_png_sig, file_sig, PNG_SIG_LEN) == 0) {
        return im_png_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "BM", 2) == 0) {
        return im_bmp_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "8BPS", 4) == 0) {
        return im_psd_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "P1", 2) == 0) {
        return im_p1_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "P2", 2) == 0) {
        return im_p2_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "P3", 2) == 0) {
        return im_p3_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "P4", 2) == 0) {
        return im_p4_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "P5", 2) == 0) {
        return im_p5_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else if(im_memcmp(file_sig, "P6", 2) == 0) {
        return im_p6_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    } else {
        return NULL;
    }

    fprintf(stderr, "ERROR: File signature does not match any known image formats.\n");
    return NULL;
}

#endif // IM_IMPL
