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
IM_API char *im_load(const char *image_path, int *width, int *height, int *number_of_channels, int desired_channels) {

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


#ifndef IM_NO_ERRORS
#define IM_ERROR(...) \
    do { \
        printf("[ERROR] "); \
        printf(__VA_ARGS__); \
        printf("Corrupt Png."); \
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
#define IM_TRUE 1
#define IM_FALSE 0

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
    size_t file_size;
    size_t bytes_read;
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
    char *png_pixels; /* the actual pixels of the image, uncompressed. */
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

static char *im__read_entire_file(const char *file_path, size_t *bytes_read) {
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

static void im_png_print_bytes(void *bytes_in, size_t len) {
    uint8_t *bytes = bytes_in;
    for(size_t i = 0; i < len; i++) {
        printf("%u ", bytes[i]);
    }
    printf("\n");
}

static void im_png_print_string(const char* str, size_t len) {
    size_t i;
    for(i = 0; i < len; i++) {
        printf("%c ", str[i]);
    }
    printf("\n");
}

static uint8_t *im_png_reverse_bytes(void *buf_in, size_t buf_len) {
    uint8_t *buf = buf_in;
    size_t i;
    uint8_t temp;
    for(i = 0; i < buf_len / 2; i++) {
        temp = buf[i];
        buf[i] = buf[buf_len - i - 1];
        buf[buf_len - i - 1] = temp;
    }
    return buf;
}

static void im_png_read_bytes(im_png_info *info, void* buf, const size_t bytes_to_read) {
    if(info->bytes_read + bytes_to_read <= info->file_size) {
        if(buf != 0) { // we only copy the data if the user wants to pass in a buffer
            im_memcpy(buf, info->png_file + info->bytes_read, bytes_to_read);
        }
        info->bytes_read += bytes_to_read;
    } else {
        fprintf(stderr, "Error: %s(): tried to read bytes past end of file, not going to read.", __func__);
    }
}

static void im_png_read_bytes_and_reverse(im_png_info *info, void* buf, const size_t bytes_to_read) {
    if(info->bytes_read + bytes_to_read <= info->file_size) {
        if(buf != 0) { // we only copy the data if the user wants to pass in a buffer
            im_memcpy(buf, info->png_file + info->bytes_read, bytes_to_read);
        }
        info->bytes_read += bytes_to_read;
        im_png_reverse_bytes(buf, bytes_to_read);
    } else {
        fprintf(stderr, "Error: %s(): tried to read bytes past end of file, not going to read.", __func__);
    }
}

size_t im__ceil(size_t x, size_t y) {
    return (x + y - 1) / y;
}

static void im_png_parse_chunk_IHDR(im_png_info *info) {
    uint32_t ihdr_data_len = 0;
    im_png_read_bytes_and_reverse(info, &ihdr_data_len, PNG_CHUNK_DATA_LEN); // this is guarunteed to be 13 in the spec, but we read anyway so that we don't fuck up the offset.
    printf("ihdr_data_length: %d\n", ihdr_data_len);
    if(ihdr_data_len != 13u){
        IM_ERR("Length section of ihdr chunk is not 13.");
    }

    char ihdr_chunk_type[4];
    im_png_read_bytes(info, &ihdr_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, ihdr_chunk_type);
    if(!info->first_ihdr) IM_ERR("Multiple IHDR.");

    im_png_read_bytes_and_reverse(info, &info->width, 4);
    im_png_read_bytes_and_reverse(info, &info->height, 4);

    im_png_read_bytes_and_reverse(info, &info->bits_per_channel, 1);
    im_png_read_bytes_and_reverse(info, &info->color_type, 1);
    im_png_read_bytes_and_reverse(info, &info->compression_method, 1);
    im_png_read_bytes_and_reverse(info, &info->filter_method, 1);
    im_png_read_bytes_and_reverse(info, &info->interlace_method, 1);

    uint32_t crc;
    im_png_read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
    printf("ihdr_crc: ");
    im_png_print_bytes(&crc, PNG_CHUNK_CRC_LEN);

#ifndef IM_NO_ERRORS
    if(info->color_type == 1 || info->color_type > 6)
        IM_ERR("Invalid color type. Expected 0, 2, 3, 4, or 6, got: %u", info->color_type);
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
    if(info->compression_method !=0)
        IM_ERR("Compression method is supposed to be 0, but it's: %u.", info->compression_method);
    if(info->filter_method !=0)
        IM_ERR("Filter method is supposed to be 0, but it's %u.", info->filter_method);
    if(info->interlace_method !=0 && info->interlace_method !=1)
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

static void im_png_parse_chunk_gAMA(im_png_info *info) {
    uint32_t gAMA_data_len = 0;
    im_png_read_bytes_and_reverse(info, &gAMA_data_len, PNG_CHUNK_DATA_LEN); /* this is guarunteed to be 13 in the spec, but we read anyway so that we don't fuck up the offset. */
    printf("gAMA_data_length: %d\n", gAMA_data_len);
    if(gAMA_data_len != 4u){
        IM_ERR("Length section of gAMA chunk is not 13.");
    }

    char gAMA_chunk_type[4];
    im_png_read_bytes(info, &gAMA_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, gAMA_chunk_type);

    uint32_t tmp;
    im_png_read_bytes_and_reverse(info, &tmp, 4);
    info->gamma = tmp / 100000.0;
    printf("gAMA chunk: gamma = %.5f\n", info->gamma);

    uint32_t crc;
    im_png_read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
}

static void im_png_parse_chunk_cHRM(im_png_info *info) {
    uint32_t cHRM_data_len = 0;
    im_png_read_bytes_and_reverse(info, &cHRM_data_len, PNG_CHUNK_DATA_LEN); /* this is guarunteed to be 13 in the spec, but we read anyway so that we don't fuck up the offset. */
    printf("cHRM_data_length: %d\n", cHRM_data_len);
    if(cHRM_data_len != 32u){
        IM_ERR("Length section of cHRM chunk is not 32.");
    }

    char cHRM_chunk_type[4];
    im_png_read_bytes(info, &cHRM_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, cHRM_chunk_type);

    uint32_t tmp;
    im_png_read_bytes_and_reverse(info, &tmp, 4);
    info->white_x = tmp / 100000.0;
    im_png_read_bytes_and_reverse(info, &tmp, 4);
    info->white_y = tmp / 100000.0;
    im_png_read_bytes_and_reverse(info, &tmp, 4);
    info->red_x = tmp / 100000.0;
    im_png_read_bytes_and_reverse(info, &tmp, 4);
    info->red_y = tmp / 100000.0;
    im_png_read_bytes_and_reverse(info, &tmp, 4);
    info->green_x = tmp / 100000.0;
    im_png_read_bytes_and_reverse(info, &tmp, 4);
    info->green_y = tmp / 100000.0;
    im_png_read_bytes_and_reverse(info, &tmp, 4);
    info->blue_x = tmp / 100000.0;
    im_png_read_bytes_and_reverse(info, &tmp, 4);
    info->blue_y = tmp / 100000.0;
    printf("white_x = %.5f\n", info->white_x);
    printf("white_y = %.5f\n", info->white_y);
    printf("red_x = %.5f\n", info->red_x);
    printf("red_y = %.5f\n", info->red_y);
    printf("green_x = %.5f\n", info->green_x);
    printf("green_y = %.5f\n", info->green_y);
    printf("blue_x = %.5f\n", info->blue_x);
    printf("blue_y = %.5f\n", info->blue_y);

    uint32_t crc;
    im_png_read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
}

static void im_png_parse_chunk_bKGD(im_png_info *info) {
    uint32_t bKGD_data_len = 0;
    im_png_read_bytes_and_reverse(info, &bKGD_data_len, PNG_CHUNK_DATA_LEN); /* this is guarunteed to be 13 in the spec, but we read anyway so that we don't fuck up the offset. */
    printf("bKGD_data_length: %d\n", bKGD_data_len);

    char bKGD_chunk_type[4];
    im_png_read_bytes(info, &bKGD_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, bKGD_chunk_type);

    switch(info->color_type) {
        case 0:
        case 4: {
            #ifndef IM_NO_ERRORS
            if(bKGD_data_len != 2u){
                IM_ERR("For color type %d, data len is supposed to be 2. data_len is: %d.", info->color_type, bKGD_data_len);
            }
            #endif
            im_png_read_bytes_and_reverse(info, &info->bkgd_gray, 2); /* 2-byte big-endian */
            break;
        }
        case 2:
        case 6: {
            #ifndef IM_NO_ERRORS
            if(bKGD_data_len != 6u){
                IM_ERR("For color type %d, data_len is supposed to be 6. data_len is: %d.", info->color_type, bKGD_data_len);
            }
            #endif
            im_png_read_bytes_and_reverse(info, &info->bkgd_r, 2);
            im_png_read_bytes_and_reverse(info, &info->bkgd_g, 2);
            im_png_read_bytes_and_reverse(info, &info->bkgd_b, 2);
            break;
        }
        case 3: {
            #ifndef IM_NO_ERRORS
            if(bKGD_data_len != 1u){
                IM_ERR("For color type 3, data_len is supposed to be 1. data_len is: %d.", bKGD_data_len);
            }
            #endif
            im_png_read_bytes(info, &info->bkgd_palette_idx, 1);
            break;
        }
    }

    uint32_t crc;
    im_png_read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
}

static void im_png_parse_chunk_tIME(im_png_info *info) {
    uint32_t tIME_data_len = 0;
    im_png_read_bytes_and_reverse(info, &tIME_data_len, PNG_CHUNK_DATA_LEN); /* this is guarunteed to be 13 in the spec, but we read anyway so that we don't fuck up the offset. */
    printf("tIME_data_length: %d\n", tIME_data_len);
    if(tIME_data_len != 7u){
        IM_ERR("Length section of tIME chunk is not 13.");
    }

    char tIME_chunk_type[4];
    im_png_read_bytes(info, &tIME_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, tIME_chunk_type);

    im_png_read_bytes_and_reverse(info, &info->year, 2);
    im_png_read_bytes_and_reverse(info, &info->month, 1);
    im_png_read_bytes_and_reverse(info, &info->day, 1);
    im_png_read_bytes_and_reverse(info, &info->hour, 1);
    im_png_read_bytes_and_reverse(info, &info->minute, 1);
    im_png_read_bytes_and_reverse(info, &info->second, 1);

    uint32_t crc;
    im_png_read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
}

static void im_png_parse_chunk_IDAT(im_png_info *info) {
    uint32_t IDAT_data_len = 0;
    im_png_read_bytes_and_reverse(info, &IDAT_data_len, PNG_CHUNK_DATA_LEN);
    printf("IDAT_data_length: %d\n", IDAT_data_len);

    char IDAT_chunk_type[4];
    im_png_read_bytes(info, &IDAT_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, IDAT_chunk_type);

    if(info->compression_method == 0) {
        if(info->idat_count == 0) {


            info->idat_count++;;

            /* we skip the first two bytes of the first IDAT chunk because the first two bytes don't contain any compressed data. */
        }
    }

    uint32_t crc;
    im_png_read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
    printf("ihdr_crc: ");
    im_png_print_bytes(&crc, PNG_CHUNK_CRC_LEN);
}

static void im_png_parse_chunk_tEXT(im_png_info *info) {
    uint32_t tEXT_data_len = 0;
    im_png_read_bytes_and_reverse(info, &tEXT_data_len, PNG_CHUNK_DATA_LEN);
    printf("tEXT_data_length: %d\n", tEXT_data_len);

    char tEXT_chunk_type[4];
    im_png_read_bytes(info, &tEXT_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: %.*s\n", PNG_CHUNK_TYPE_LEN, tEXT_chunk_type);

    char keyword[80] = {0};
    char at = 0;
    int counter = 0;
    do {
        if(counter >= 79) break;
        im_png_read_bytes(info, &at, 1);
        keyword[counter++] = at;
    } while(at != '\0');

    size_t text_len = tEXT_data_len - counter;
    char *text = (char*)malloc(text_len + 1);
    im_png_read_bytes(info, text, text_len);
    text[text_len] = '\0';

    printf("keyword: %s\n", keyword);
    printf("Text: %s\n", text);

    free(text);

    uint32_t crc;
    im_png_read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
}

static void im_png_parse_chunk_IEND(im_png_info *info) {
    uint32_t IEND_data_len = 0;
    im_png_read_bytes_and_reverse(info, &IEND_data_len, PNG_CHUNK_DATA_LEN); /* this is guarunteed to be 13 in the spec, but we read anyway so that we don't fuck up the offset. */
    printf("IEND_data_length: %d\n", IEND_data_len);
    if(IEND_data_len != 0u){
        IM_ERR("Length section of IEND chunk is not 0.");
    }

    char IEND_chunk_type[4];
    im_png_read_bytes(info, &IEND_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, IEND_chunk_type);

    uint32_t crc;
    im_png_read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
}

char *get_next_chunk(im_png_info *info) {
    if(info->png_file + info->bytes_read < info->png_file + info->file_size) {
        return info->png_file + info->bytes_read;
    } else {
        fprintf(stderr, "Error: %s() Tried to get next chunk after end of file", __func__);
        return NULL;
    }
}

char *get_next_chunk_type(im_png_info *info) {
    if(info->png_file + info->bytes_read < info->png_file + info->file_size) {
        return info->png_file + info->bytes_read + PNG_CHUNK_DATA_LEN;
    } else {
        fprintf(stderr, "Error: %s() Tried to get next chunk after end of file", __func__);
        return NULL;
    }
}

static void skip_chunk(im_png_info *info) {
    uint32_t length_be = 0;
    im_png_read_bytes(info, &length_be, 4);
    im_png_reverse_bytes(&length_be, 4);

    /* Skip the chunk type (4 bytes), chunk data (length_be bytes), and CRC (4 bytes) */
    size_t bytes_to_skip = PNG_CHUNK_TYPE_LEN + length_be + PNG_CHUNK_CRC_LEN;

    /* Advance the offset */
    info->bytes_read += bytes_to_skip;
}

static void im_png_peek_bytes(im_png_info *info, void* buf, char *offset, const size_t bytes_to_read) {
    if(offset < info->png_file + info->file_size) {
        im_memcpy(buf, offset, bytes_to_read);
    } else {
        fprintf(stderr, "Error: %s(): tried to read bytes past end of file, not going to read.", __func__);
    }
}

static char* im_png_peek_next_chunk(im_png_info *info, char *current_chunk) {
    uint32_t data_length = 0;
    im_png_peek_bytes(info, &data_length, current_chunk, PNG_CHUNK_DATA_LEN);
    im_png_reverse_bytes(&data_length, PNG_CHUNK_DATA_LEN);
    printf("DATA LENGTH: %d\n", data_length);

    return current_chunk + PNG_CHUNK_DATA_LEN + PNG_CHUNK_TYPE_LEN + data_length + PNG_CHUNK_CRC_LEN;
}

typedef struct {
    uint8_t *data;
    size_t bitpos; /* bit offset from start */
} im__bitstream;

uint32_t consume_bits(im__bitstream *bs, int n) {
    uint32_t val = 0;
    for (int i = 0; i < n; i++) {
        size_t byte_index = bs->bitpos / 8;
        int bit_index = bs->bitpos % 8;
        val |= ((bs->data[byte_index] >> bit_index) & 1) << i;
        bs->bitpos++;
    }
    return val;
}

static inline void align_next_byte(im__bitstream *bs) {
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

static void im_png_build_fixed_huffman_tree() {
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
static int decode_fixed_literal_length(im__bitstream *bs) {
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
static int decode_fixed_distance(im__bitstream *bs) {
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


static void build_huffman_tree(huffman_tree *tree, uint8_t *lengths, int count) {
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


static int decode_symbol(im__bitstream *bs, huffman_tree *tree, int max_symbols) {
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

static char *im_png_decompress(im_png_info *info, char *current_IDAT_chunk, size_t *idat_chunk_count) {

    uint32_t comp_data_size = 0;
    uint32_t tmp = 0;

    char *start = current_IDAT_chunk;

    /* find the total size of the compressed data */
    while(*(uint32_t*)(current_IDAT_chunk + PNG_CHUNK_DATA_LEN) == CHUNK_IDAT) {

        im_memcpy(&tmp, current_IDAT_chunk, PNG_CHUNK_DATA_LEN);
        im_png_reverse_bytes(&tmp, PNG_CHUNK_DATA_LEN);
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
        im_png_reverse_bytes(&current_chunk_data_len, PNG_CHUNK_DATA_LEN);

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
        size_t bytes_per_scanline = im__ceil(info->width * info->channel_count * info->bits_per_channel, 8);
        size_t image_size_after_decompression = info->height * (bytes_per_scanline + 1); /* +1 per scanline for filter byte */
        info->png_pixels = malloc(image_size_after_decompression);
        struct {
            uint8_t BFINAL;
            uint8_t BTYPE;
        }block_header;
        size_t offset = 0;
        im__bitstream bs = { (uint8_t*)compressed_data, 0 };
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
                        IM_ERR("Corrupted stored block!\n");
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
                    
                    printf("HLIT=%d, HDIST=%d, HCLEN=%d\n", HLIT, HDIST, HCLEN);
                    
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
                    printf("Code length tree:\n");
                    for (int i = 0; i < 19; i++) {
                        if (code_length_tree[i].len > 0) {
                            printf("  Symbol %d: len=%d, code=%d\n", i, code_length_tree[i].len, code_length_tree[i].code);
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
                        
                        printf("Decoded symbol %d at position %d\n", symbol, i);
                        
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

    return info->png_pixels;
}

char *im_png_load(char *image_file, size_t file_size, int *width, int *height, int *num_channels, int desired_channels) {

    im_png_info info = {0};
    info.first_ihdr = IM_TRUE;
    info.png_file = image_file;
    info.file_size = file_size;

    im_png_read_bytes(&info, 0, 8);
    printf("png_sig: ");
    im_png_print_bytes(info.png_file, PNG_SIG_LEN);

    char *next_chunk_type = NULL;
    next_chunk_type = get_next_chunk_type(&info);

    while(*(uint32_t*)next_chunk_type != CHUNK_IEND) {
        next_chunk_type = get_next_chunk_type(&info);
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
                im_png_decompress(&info, next_chunk_type - PNG_CHUNK_DATA_LEN, &idat_chunk_count);
                /*im_png_parse_chunk_IDAT(&info); */
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
                im_png_parse_chunk_tEXT(&info);
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

IM_API char *im_load(const char *image_path, int *width, int *height, int *number_of_channels, int desired_channels) {

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
    im_memcpy(file_sig, image_file, PNG_SIG_LEN);

    if(im_memcmp(im_png_sig, file_sig, PNG_SIG_LEN) == 0) {
        return im_png_load(image_file, file_size, width, height, number_of_channels, desired_channels);
    }

    fprintf(stderr, "ERROR: File signature does not match any known image formats.\n");
    return NULL;
}
#endif // IM_IMPLEMENTATION
