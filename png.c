#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>

#define PNG_SIG_LEN 8
#define PNG_CHUNK_TYPE_LEN 4
#define PNG_CHUNK_DATA_LEN 4
#define PNG_CHUNK_CRC_LEN 4

#ifndef IM_NO_ERRORS
#define IM_PRINT(...) \
    do { \
        printf("Error: "); \
        printf(__VA_ARGS__); \
        printf("Corrupt Png."); \
        printf("\n"); \
    } while(0)
#define IM_ERR(...) IM_PRINT(__VA_ARGS__)
#else
#define IM_PRINT(...) ((void)0)
#define IM_ERR(...)((void)0)
#endif


#define STR_TO_UINT(a,b,c,d) \
    (((uint32_t)(a))       | \
     ((uint32_t)(b) << 8)  | \
     ((uint32_t)(c) << 16) | \
     ((uint32_t)(d) << 24))

uint8_t png_sig[PNG_SIG_LEN] = {137, 80, 78, 71, 13, 10, 26, 10};

typedef enum {
    GRAYSCALE = 0,
    RGB = 2,
    PALETTE = 3, // Special colour mode where you use a pre-defined palette in order to choose your colours. And each pixel is a palette index.
    GRAYSCALE_A = 4,
    RGBA = 6
}im_ihdr_color_types;

typedef enum {
    UNCOMPRESSED,
    FIXED_HUFFMAN,
    DYNAMIC_HUFFMAN,
    RESERVED
}im_compression_types;

typedef enum {
    // IHDR has to be the first chunk in the file.
    CHUNK_IHDR = STR_TO_UINT('I','H','D','R'),

    // these ones have to appear in the file before PLTE and IDAT
    CHUNK_cHRM = STR_TO_UINT('c','H','R','M'),
    CHUNK_iCCP = STR_TO_UINT('i','C','C','P'),
    CHUNK_sBIT = STR_TO_UINT('s','B','I','T'),
    CHUNK_sRGB = STR_TO_UINT('s','R','G','B'),

    // PLTE is optional, but has to appear after IHDR
    CHUNK_PLTE = STR_TO_UINT('P','L','T','E'),

    CHUNK_bKGD = STR_TO_UINT('b','K','G','D'),
    CHUNK_hIST = STR_TO_UINT('h','I','S','T'),
    CHUNK_tRNS = STR_TO_UINT('t','R','N','S'),
    CHUNK_pHYs = STR_TO_UINT('p','H','Y','s'),
    CHUNK_sPLT = STR_TO_UINT('s','P','L','T'),

    // IDAT (has to appear after PLTE if PLTE is present, if it's not present, it has to appear after IHDR).
    CHUNK_IDAT = STR_TO_UINT('I','D','A','T'),

    CHUNK_iTXt = STR_TO_UINT('i','T','X','t'),
    CHUNK_tEXt = STR_TO_UINT('t','E','X','t'),
    CHUNK_zTXt = STR_TO_UINT('z','T','X','t'),
    CHUNK_tIME = STR_TO_UINT('t','I','M','E'),
    CHUNK_gAMA = STR_TO_UINT('g','A','M','A'),

    // IEND has to appear after IDAT, and has to be the last chunk in the file.
    CHUNK_IEND = STR_TO_UINT('I','E','N','D')
}im_chunk_types;

typedef int im_bool;
#define IM_TRUE 1
#define IM_FALSE 0
typedef struct{
    char *png_file;
    size_t file_size;
    size_t bytes_read;
    uint32_t width;
    uint32_t height;
    uint8_t channel_count; // channels are called "samples" in the spec, but that's stupid, so I won't call them samples.
    uint8_t bits_per_channel;
    uint8_t color_type;
    uint8_t compression_method;
    uint8_t filter_method;
    uint8_t interlace_method;
    im_bool first_ihdr;
    int idat_count;
    //gamma
    double gamma;
    // chromaticity
    double white_x;
    double white_y;
    double red_x;
    double red_y;
    double green_x;
    double green_y;
    double blue_x;
    double blue_y;

    // background image
    // no alpha allowed for background images in the spec.
    uint8_t bkgd_palette_idx;
    uint16_t bkgd_r;
    uint16_t bkgd_g;
    uint16_t bkgd_b;
    uint16_t bkgd_gray;

    // time
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    char *png_pixels; // the actual pixels of the image, uncompressed.
}png_info;

static char *im__read_entire_file(const char *file_path, size_t *bytes_read) {
    struct stat st;
    if(stat(file_path, &st) != 0) return NULL;
    size_t file_size = st.st_size;

    int fd = open(file_path, O_RDONLY);
    if(fd < 0) return NULL;

    void *buf = malloc(file_size);
    if(!buf) { close(fd); return NULL; }

    ssize_t n = read(fd, buf, file_size);
    close(fd);
    if(n != (ssize_t)file_size) { free(buf); return NULL; }

    *bytes_read = file_size;
    return buf;
}

static void im__print_bytes(void *bytes_in, size_t len) {
    uint8_t *bytes = bytes_in;
    for(size_t i = 0; i < len; i++) {
        printf("%u ", bytes[i]);
    }
    printf("\n");
}

static void im__print_string(const char* str, size_t len) {
    for(size_t i = 0; i < len; i++) {
        printf("%c ", str[i]);
    }
    printf("\n");
}

static uint8_t *im__reverse_bytes(void *buf_in, size_t buf_len) {
    uint8_t *buf = buf_in;
    for(size_t i = 0; i < buf_len / 2; i++) {
        uint8_t temp = buf[i];
        buf[i] = buf[buf_len - i - 1];
        buf[buf_len - i - 1] = temp;
    }
    return buf;
}

static void im__read_bytes(png_info *info, void* buf, const size_t bytes_to_read) {
    if(info->png_file + info->bytes_read < info->png_file + info->file_size) {
        memcpy(buf, info->png_file + info->bytes_read, bytes_to_read);
        info->bytes_read += bytes_to_read;
    } else {
        fprintf(stderr, "Error: %s(): tried to read bytes past end of file, not going to read.", __func__);
    }
}


static void im__read_bytes_and_reverse(png_info *info, void* buf, const size_t bytes_to_read) {
    if(info->png_file + info->bytes_read < info->png_file + info->file_size) {
        memcpy(buf, info->png_file + info->bytes_read, bytes_to_read);
        info->bytes_read += bytes_to_read;
        im__reverse_bytes(buf, bytes_to_read);
    } else {
        fprintf(stderr, "Error: %s(): tried to read bytes past end of file, not going to read.", __func__);
    }
}

size_t im__ceil(size_t x, size_t y) {
    return (x + y - 1) / y;
}

static void im__parse_chunk_IHDR(png_info *info) {
    uint32_t ihdr_data_len = 0;
    im__read_bytes_and_reverse(info, &ihdr_data_len, PNG_CHUNK_DATA_LEN); // this is guarunteed to be 13 in the spec, but we read anyway so that we don't fuck up the offset.
    printf("ihdr_data_length: %d\n", ihdr_data_len);
    if(ihdr_data_len != 13u){
        IM_ERR("Length section of ihdr chunk is not 13. Corrupt PNG.");
    }

    char ihdr_chunk_type[4];
    im__read_bytes(info, &ihdr_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, ihdr_chunk_type);
    if(!info->first_ihdr) IM_ERR("Multiple IHDR, Corrupt PNG.");

    im__read_bytes_and_reverse(info, &info->width, 4);
    im__read_bytes_and_reverse(info, &info->height, 4);

    im__read_bytes_and_reverse(info, &info->bits_per_channel, 1);
    im__read_bytes_and_reverse(info, &info->color_type, 1);
    im__read_bytes_and_reverse(info, &info->compression_method, 1);
    im__read_bytes_and_reverse(info, &info->filter_method, 1);
    im__read_bytes_and_reverse(info, &info->interlace_method, 1);

    uint32_t crc;
    im__read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
    printf("ihdr_crc: ");
    im__print_bytes(&crc, PNG_CHUNK_CRC_LEN);

#ifndef IM_NO_ERRORS
    if(info->color_type == 1 || info->color_type > 6)
        IM_ERR("Invalid color type. Expected 0, 2, 3, 4, or 6, got: %u Corrupt PNG.", info->color_type);
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
        IM_ERR("Compression method is supposed to be 0, but it's: %u. Corrupt PNG.", info->compression_method);
    if(info->filter_method !=0)
        IM_ERR("Filter method is supposed to be 0, but it's %u. Corrupt PNG.", info->filter_method);
    if(info->interlace_method !=0 && info->interlace_method !=1)
        IM_ERR("Interlace method is supposed to be 0 or 1, but it's %u. Corrupt PNG.", info->interlace_method);
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

static void im__parse_chunk_gAMA(png_info *info) {
    uint32_t gAMA_data_len = 0;
    im__read_bytes_and_reverse(info, &gAMA_data_len, PNG_CHUNK_DATA_LEN); // this is guarunteed to be 13 in the spec, but we read anyway so that we don't fuck up the offset.
    printf("gAMA_data_length: %d\n", gAMA_data_len);
    if(gAMA_data_len != 4u){
        IM_ERR("Length section of gAMA chunk is not 13. Corrupt PNG.");
    }

    char gAMA_chunk_type[4];
    im__read_bytes(info, &gAMA_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, gAMA_chunk_type);

    uint32_t tmp;
    im__read_bytes_and_reverse(info, &tmp, 4);
    info->gamma = tmp / 100000.0;
    printf("gAMA chunk: gamma = %.5f\n", info->gamma);

    uint32_t crc;
    im__read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
}

static void im__parse_chunk_cHRM(png_info *info) {
    uint32_t cHRM_data_len = 0;
    im__read_bytes_and_reverse(info, &cHRM_data_len, PNG_CHUNK_DATA_LEN); // this is guarunteed to be 13 in the spec, but we read anyway so that we don't fuck up the offset.
    printf("cHRM_data_length: %d\n", cHRM_data_len);
    if(cHRM_data_len != 32u){
        IM_ERR("Length section of cHRM chunk is not 32. Corrupt PNG.");
    }

    char cHRM_chunk_type[4];
    im__read_bytes(info, &cHRM_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, cHRM_chunk_type);

    uint32_t tmp;
    im__read_bytes_and_reverse(info, &tmp, 4);
    info->white_x = tmp / 100000.0;
    im__read_bytes_and_reverse(info, &tmp, 4);
    info->white_y = tmp / 100000.0;
    im__read_bytes_and_reverse(info, &tmp, 4);
    info->red_x = tmp / 100000.0;
    im__read_bytes_and_reverse(info, &tmp, 4);
    info->red_y = tmp / 100000.0;
    im__read_bytes_and_reverse(info, &tmp, 4);
    info->green_x = tmp / 100000.0;
    im__read_bytes_and_reverse(info, &tmp, 4);
    info->green_y = tmp / 100000.0;
    im__read_bytes_and_reverse(info, &tmp, 4);
    info->blue_x = tmp / 100000.0;
    im__read_bytes_and_reverse(info, &tmp, 4);
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
    im__read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
}

static void im__parse_chunk_bKGD(png_info *info) {
    uint32_t bKGD_data_len = 0;
    im__read_bytes_and_reverse(info, &bKGD_data_len, PNG_CHUNK_DATA_LEN); // this is guarunteed to be 13 in the spec, but we read anyway so that we don't fuck up the offset.
    printf("bKGD_data_length: %d\n", bKGD_data_len);

    char bKGD_chunk_type[4];
    im__read_bytes(info, &bKGD_chunk_type, PNG_CHUNK_TYPE_LEN);
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
            im__read_bytes_and_reverse(info, &info->bkgd_gray, 2); // 2-byte big-endian
            break;
        }
        case 2:
        case 6: {
            #ifndef IM_NO_ERRORS
            if(bKGD_data_len != 6u){
                IM_ERR("For color type %d, data_len is supposed to be 6. data_len is: %d.", info->color_type, bKGD_data_len);
            }
            #endif
            im__read_bytes_and_reverse(info, &info->bkgd_r, 2);
            im__read_bytes_and_reverse(info, &info->bkgd_g, 2);
            im__read_bytes_and_reverse(info, &info->bkgd_b, 2);
            break;
        }
        case 3: {
            #ifndef IM_NO_ERRORS
            if(bKGD_data_len != 1u){
                IM_ERR("For color type 3, data_len is supposed to be 1. data_len is: %d.", bKGD_data_len);
            }
            #endif
            im__read_bytes(info, &info->bkgd_palette_idx, 1);
            break;
        }
    }

    uint32_t crc;
    im__read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
}

static void im__parse_chunk_tIME(png_info *info) {
    uint32_t tIME_data_len = 0;
    im__read_bytes_and_reverse(info, &tIME_data_len, PNG_CHUNK_DATA_LEN); // this is guarunteed to be 13 in the spec, but we read anyway so that we don't fuck up the offset.
    printf("tIME_data_length: %d\n", tIME_data_len);
    if(tIME_data_len != 7u){
        IM_ERR("Length section of tIME chunk is not 13. Corrupt PNG.");
    }

    char tIME_chunk_type[4];
    im__read_bytes(info, &tIME_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, tIME_chunk_type);

    im__read_bytes_and_reverse(info, &info->year, 2);
    im__read_bytes_and_reverse(info, &info->month, 1);
    im__read_bytes_and_reverse(info, &info->day, 1);
    im__read_bytes_and_reverse(info, &info->hour, 1);
    im__read_bytes_and_reverse(info, &info->minute, 1);
    im__read_bytes_and_reverse(info, &info->second, 1);

    uint32_t crc;
    im__read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
}

static void im__parse_chunk_IDAT(png_info *info) {
    uint32_t IDAT_data_len = 0;
    im__read_bytes_and_reverse(info, &IDAT_data_len, PNG_CHUNK_DATA_LEN);
    printf("IDAT_data_length: %d\n", IDAT_data_len);

    char IDAT_chunk_type[4];
    im__read_bytes(info, &IDAT_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, IDAT_chunk_type);

    if(info->compression_method == 0) {
        if(info->idat_count == 0) {


            info->idat_count++;;

            // we skip the first two bytes of the first IDAT chunk because the first two bytes don't contain any compressed data.
        }
    }

    uint32_t crc;
    im__read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
    printf("ihdr_crc: ");
    im__print_bytes(&crc, PNG_CHUNK_CRC_LEN);
}

static void im__parse_chunk_tEXT(png_info *info) {
    uint32_t tEXT_data_len = 0;
    im__read_bytes_and_reverse(info, &tEXT_data_len, PNG_CHUNK_DATA_LEN);
    printf("tEXT_data_length: %d\n", tEXT_data_len);

    char tEXT_chunk_type[4];
    im__read_bytes(info, &tEXT_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: %.*s\n", PNG_CHUNK_TYPE_LEN, tEXT_chunk_type);

    char keyword[80] = {0};
    char at;
    int counter = 0;
    do {
        if(counter >= 79) break;
        im__read_bytes(info, &at, 1);
        keyword[counter++] = at;
    } while(at != '\0');

    size_t text_len = tEXT_data_len - counter;
    char *text = (char*)malloc(text_len + 1);
    im__read_bytes(info, text, text_len);
    text[text_len] = '\0';

    printf("keyword: %s\n", keyword);
    printf("Text: %s\n", text);

    free(text);

    uint32_t crc;
    im__read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
}

static void im__parse_chunk_IEND(png_info *info) {
    uint32_t IEND_data_len = 0;
    im__read_bytes_and_reverse(info, &IEND_data_len, PNG_CHUNK_DATA_LEN); // this is guarunteed to be 13 in the spec, but we read anyway so that we don't fuck up the offset.
    printf("IEND_data_length: %d\n", IEND_data_len);
    if(IEND_data_len != 0u){
        IM_ERR("Length section of IEND chunk is not 0. Corrupt PNG.");
    }

    char IEND_chunk_type[4];
    im__read_bytes(info, &IEND_chunk_type, PNG_CHUNK_TYPE_LEN);
    printf("chunk type: ");
    printf("%.*s\n", PNG_CHUNK_TYPE_LEN, IEND_chunk_type);

    uint32_t crc;
    im__read_bytes_and_reverse(info, &crc, PNG_CHUNK_CRC_LEN);
}

char *get_next_chunk(png_info *info) {
    if(info->png_file + info->bytes_read < info->png_file + info->file_size) {
        return info->png_file + info->bytes_read;
    } else {
        fprintf(stderr, "Error: %s() Tried to get next chunk after end of file", __func__);
        return NULL;
    }
}

char *get_next_chunk_type(png_info *info) {
    if(info->png_file + info->bytes_read < info->png_file + info->file_size) {
        return info->png_file + info->bytes_read + PNG_CHUNK_DATA_LEN;
    } else {
        fprintf(stderr, "Error: %s() Tried to get next chunk after end of file", __func__);
        return NULL;
    }
}

static void skip_chunk(png_info *info) {
    uint32_t length_be = 0;
    im__read_bytes(info, &length_be, 4);
    im__reverse_bytes(&length_be, 4);

    // Skip the chunk type (4 bytes), chunk data (length_be bytes), and CRC (4 bytes)
    size_t bytes_to_skip = PNG_CHUNK_TYPE_LEN + length_be + PNG_CHUNK_CRC_LEN;

    // Advance the offset
    info->bytes_read += bytes_to_skip;
}

static void im__peek_bytes(png_info *info, void* buf, char *offset, const size_t bytes_to_read) {
    if(offset < info->png_file + info->file_size) {
        memcpy(buf, offset, bytes_to_read);
    } else {
        fprintf(stderr, "Error: %s(): tried to read bytes past end of file, not going to read.", __func__);
    }
}

static char* im__peek_next_chunk(png_info *info, char *current_chunk) {
    uint32_t data_length = 0;
    im__peek_bytes(info, &data_length, current_chunk, PNG_CHUNK_DATA_LEN);
    im__reverse_bytes(&data_length, PNG_CHUNK_DATA_LEN);
    printf("DATA LENGTH: %d\n", data_length);

    return current_chunk + PNG_CHUNK_DATA_LEN + PNG_CHUNK_TYPE_LEN + data_length + PNG_CHUNK_CRC_LEN;
}

typedef struct {
    uint8_t *data;
    size_t bitpos; // bit offset from start
} im__bitstream;

uint32_t read_bits(im__bitstream *bs, int n) {
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
    if (bs->bitpos % 8 != 0)
        bs->bitpos += 8 - (bs->bitpos % 8);
}

static char *decompress_png(png_info *info, char *current_IDAT_chunk) {

    uint32_t comp_data_size = 0;
    uint32_t tmp = 0;
    
    size_t idat_chunk_count = 0;
    char *start = current_IDAT_chunk;

    // find the total size of the compressed data
    while(*(uint32_t*)(current_IDAT_chunk + PNG_CHUNK_DATA_LEN) == CHUNK_IDAT) {

        memcpy(&tmp, current_IDAT_chunk, PNG_CHUNK_DATA_LEN);
        im__reverse_bytes(&tmp, PNG_CHUNK_DATA_LEN);
        printf(" THE FUCKING DATA LENGTH: %d\n", tmp);

        comp_data_size += tmp;
        current_IDAT_chunk = im__peek_next_chunk(info, current_IDAT_chunk);
        printf("TOTAL SIZE OF COMPRESSED DATA: %d\n", comp_data_size);
        idat_chunk_count++;
    }

    char *compressed_data = (char*)malloc(comp_data_size);
    if (!compressed_data) return NULL;

    size_t offset = 0;
    uint32_t current_chunk_data_len = 0;

    // concatenate the data sections of all the IDAT chunks together.
    // we need to do this in order to decompress the data.
    current_IDAT_chunk = start;
    while (*(uint32_t*)(current_IDAT_chunk + 4) == CHUNK_IDAT) {
        memcpy(&current_chunk_data_len, current_IDAT_chunk, PNG_CHUNK_DATA_LEN);
        im__reverse_bytes(&current_chunk_data_len, PNG_CHUNK_DATA_LEN);

        memcpy(compressed_data + offset, current_IDAT_chunk + PNG_CHUNK_DATA_LEN + PNG_CHUNK_TYPE_LEN, current_chunk_data_len);
        offset += current_chunk_data_len;

        current_IDAT_chunk += PNG_CHUNK_DATA_LEN + PNG_CHUNK_TYPE_LEN + current_chunk_data_len + PNG_CHUNK_CRC_LEN;
    }

    // this contains the compression method in the lower nibble, and the compression window size in the higher nibble.
    char *zlib_header = compressed_data;
    compressed_data += 2; // skip zlib header.
    uint8_t cmf = zlib_header[0];
    uint8_t comp_method = cmf & 0x0F;   // bits 0 - 3 | HAS TO BE 8 BECAUSE .PNG SPEC ONLY SUPPORTS DEFLATE.
    uint8_t comp_window_size_bits  = (cmf >> 4) & 0x0F; // bit 4 - 8
    uint8_t comp_window_size = 1 << (comp_window_size_bits + 8); // window = 1 << (8 + bits)

    uint8_t flg = zlib_header[1];
    uint8_t check_bits = flg & 0x1F;         // bits 0-4 | Used for integrity check
    uint8_t preset_dict_flag = (flg >> 5) & 1;  // bit 5 | HAS TO BE 0 BECAUSE .PNG SPEC SAID SO.
    uint8_t compression_level = (flg >> 6) & 3; // bits 6-7 | 0 - 3 Compression level hints. These don't matter when decompressing.

    printf("Compression method: %d (should be 8 = DEFLATE)\n", comp_method);
    printf("Compression window size: %d KB\n", comp_window_size);
    printf("check_bits: %d\n", check_bits);
    printf("preset_dict_flag: %d\n", preset_dict_flag);
    printf("Compression level: %d\n", compression_level);

    printf("%lu\n", sizeof(cmf + flg));

    if (((cmf << 8) + flg) % 31 == 0) {
        printf("Info: Integrity check successful!\ndecompressing...\n");
        size_t bytes_per_scanline = im__ceil(info->width * info->channel_count * info->bits_per_channel, 8);
        size_t image_size_after_decompression = info->height * (bytes_per_scanline + 1); // +1 per scanline for filter byte
        info->png_pixels = malloc(image_size_after_decompression);
        uint8_t is_last_block, block_type;
        size_t offset = 0;
        im__bitstream bs = { (uint8_t*)compressed_data, 0 };
        do {
            is_last_block = read_bits(&bs, 1);
            block_type = read_bits(&bs, 2);
            printf("block_type %d, is_last_block %d\n", block_type, is_last_block);
            switch(block_type) {
                case UNCOMPRESSED: {
                    printf("Copying uncompressed block!\n");
                    align_next_byte(&bs);

                    uint16_t len  = read_bits(&bs, 16);
                    uint16_t nlen = read_bits(&bs, 16);

                    if ((len ^ nlen) != 0xFFFF) {
                        fprintf(stderr, "Error: Corrupted stored block!\n");
                    }
                    for (uint16_t i = 0; i < len; i++) {
                        info->png_pixels[offset++] = (uint8_t)read_bits(&bs, 8);
                    }
                    break;
                }
                case FIXED_HUFFMAN: {
                    break;
                }
                case DYNAMIC_HUFFMAN: {
                    break;
                }
                case RESERVED: {
                    fprintf(stderr, "Error: Encountered reserved (invalid) block type!\n");
                    break;
                }
            }
        } while(!is_last_block);

    } else {
        fprintf(stderr, "Error: Integrity check failed.\n");
    }

    return info->png_pixels;
}

int main(int argc, char **argv) {
    if(argc < 2) {
        printf("Usage: png [file_name]\n");
        fprintf(stderr, "ERROR: No .png file provided!\n");
        return 1;
    }
    char *file_path = argv[1];

    png_info info = {0};
    info.first_ihdr = IM_TRUE;

    info.png_file = im__read_entire_file(file_path, &info.file_size);

    if(!info.png_file) {
        fprintf(stderr, "ERROR: Failed to read .png file.\n");
        return 1;
    }

    uint8_t parsed_sig[PNG_SIG_LEN] = {0};
    im__read_bytes(&info, parsed_sig, 8);

    if(memcmp(png_sig, parsed_sig, PNG_SIG_LEN) == 0) {
        printf("png_sig: ");
        im__print_bytes(info.png_file, PNG_SIG_LEN);
    } else {
        fprintf(stderr, "ERROR: .png signature not found. This might not be a .png file.\n");
        return 1;
    }


    char *next_chunk_type = NULL;
    next_chunk_type = get_next_chunk_type(&info);

    while(*(uint32_t*)next_chunk_type != CHUNK_IEND) {
        next_chunk_type = get_next_chunk_type(&info);
        printf("chunk: %.*s\n", 4, next_chunk_type);
        switch(*(uint32_t*)next_chunk_type)  {
            case CHUNK_IHDR:
                im__parse_chunk_IHDR(&info);
                printf("-----------------------------\n");
                break;
            case CHUNK_cHRM:
                im__parse_chunk_cHRM(&info);
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
                im__parse_chunk_bKGD(&info);
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
                char *png_pixels = decompress_png(&info, next_chunk_type - PNG_CHUNK_DATA_LEN);
                //im__parse_chunk_IDAT(&info);
                for(int i = 0; i < 4; i++) {
                    skip_chunk(&info);
                }
                printf("-----------------------------\n");
                break;
            }
            case CHUNK_iTXt:
                skip_chunk(&info);
                break;
            case CHUNK_tEXt:
                im__parse_chunk_tEXT(&info);
                printf("-----------------------------\n");
                break;
            case CHUNK_zTXt:
                skip_chunk(&info);
                break;
            case CHUNK_tIME:
                im__parse_chunk_tIME(&info);
                printf("-----------------------------\n");
                break;
            case CHUNK_gAMA:
                im__parse_chunk_gAMA(&info);
                printf("-----------------------------\n");
                break;
            case CHUNK_IEND:
                im__parse_chunk_IEND(&info);
                printf("-----------------------------\n");
                break;
            default:
                skip_chunk(&info);
                break;
        }
    }

    return 0;
}
