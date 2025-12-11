#include <stdio.h>

#define PAL_IMPLEMENTATION
#include "pal_single_header.h"

#define IM_IMPLEMENTATION
#include "im.h"

int main(int argc, char **argv) {

    if(argc < 2) {
        printf("Usage: png [file_name]\n");
        fprintf(stderr, "ERROR: No .png file provided!\n");
        return 1;
    }
    char *file_path = argv[1];

    int image_width, image_height, nr_channels;
    unsigned char *image = im_load(file_path, &image_width, &image_height, &nr_channels, 0);
    if(!image) return 0;

    pal_init();
    int window_width = 800, window_height = 600;
    pal_window *window = pal_create_window(window_width, window_height, "image_viewer", 0);
    int running = 1;
    pal_event event;
    pal_vec4 bg_color = {1.0f, 1.0f, 1.0f, 1.0f};

    while(running) {
        while(pal_poll_events(&event)) {
            switch(event.type) {
                case PAL_EVENT_WINDOW_RESIZED:
                    window_width = event.window.width;
                    window_height = event.window.height;
                    printf("%d", event.window.width);
                    break;
            }
        }

        if(pal_is_key_pressed(-1, PAL_SCAN_ESCAPE) || pal_is_key_pressed(-1, PAL_SCAN_CAPSLOCK)) {
            return 0;
        }

        size_t img_pixel_idx = 0;

        for(int y = 0; y < image_height; y++) {
            for(int x = 0; x < image_width; x++) {
#if 0
                /* PBM_TEST */
                pal_vec4 color = {0};
                color.r = (float)image[img_pixel_idx] / 255.0f;
                color.g = (float)image[img_pixel_idx] / 255.0f;
                color.b = (float)image[img_pixel_idx] / 255.0f;
                img_pixel_idx++;
                printf("pixel: %zu: %f, %f, %f, \n", img_pixel_idx, color.r, color.g, color.b);
                pal_draw_rect(window, x + 400, y + 300, 1, 1, color);

#endif
                pal_color color;
                color.r = image[img_pixel_idx++];
                color.g = image[img_pixel_idx++];
                color.b = image[img_pixel_idx++];
                color.a =  255.0f;
                pal_draw_rect(window, x + window_width / 2, y + window_height / 2, 1, 1, color);
#if 0
                /* PNG_TEST */
                float src_r = (float)image[img_pixel_idx++] / 255.0f;
                float src_g = (float)image[img_pixel_idx++] / 255.0f;
                float src_b = (float)image[img_pixel_idx++] / 255.0f;
                float src_a = (float)image[img_pixel_idx++] / 255.0f;
                
                // Alpha blend with background
                pal_vec4 color;
                color.r = src_r * src_a + bg_color.r * (1.0f - src_a);
                color.g = src_g * src_a + bg_color.g * (1.0f - src_a);
                color.b = src_b * src_a + bg_color.b * (1.0f - src_a);
                color.a = 1.0f; // Fully opaque after blending
                
                pal_draw_rect(window, x + window_width / 2, y + window_height / 2, 1, 1, color);
#endif
            }
        }
    }
    return 0;
}
