#include "png.h"

int main(int argc, char **argv) {

    if(argc < 2) {
        printf("Usage: png [file_name]\n");
        fprintf(stderr, "ERROR: No .png file provided!\n");
        return 1;
    }
    char *file_path = argv[1];

    int width, height, nr_channels;
    char *image = im_load(file_path, &width, &height, &nr_channels, 0);

    printf("width: %d, height: %d, num_channels: %d\n", width, height, nr_channels);
    return 0;
}
