#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char debug_mode = 0;
char file_name[128] = "";
int unit_size = 1;
unsigned char mem_buf[10000];
size_t mem_count = 0;
char display_mode = 0;

static char* hex_formats[] = {"%#hhx\n", "%#hx\n", "No such unit", "%#x\n"};
static char* dec_formats[] = {"%#hhd\n", "%#hd\n", "No such unit", "%#d\n"};

struct fun_desc {
    char *name;
    char index;
    void (*fun)();
};

void toggle_debug_mode();
void set_file_name();
void set_unit_size();
void load_into_memory();
void toggle_display_mode();
void memory_display();
void save_into_file();
void memory_modify();
void quit();

void toggle_debug_mode() {
    if (debug_mode == 0) {
        debug_mode = 1;
        fprintf(stderr, "Debug flag now on\n");
    } else {
        debug_mode = 0;
        fprintf(stderr, "Debug flag now off\n");
    }
}

void set_file_name() {
    printf("Enter file name: ");
    if (fgets(file_name, sizeof(file_name), stdin) != NULL) {
        file_name[strcspn(file_name, "\n")] = 0;
    }
    if (debug_mode) {
        fprintf(stderr, "Debug: file name set to '%s'\n", file_name);
    }
}

void set_unit_size() {
    char input[10];
    int size;
    printf("Enter unit size - 1, 2, or 4: ");
    if (fgets(input, sizeof(input), stdin) != NULL) {
        if (sscanf(input, "%d", &size) == 1) {
            if (size == 1 || size == 2 || size == 4) {
                unit_size = size;
                if (debug_mode) {
                    fprintf(stderr, "Debug: set size to %d\n", unit_size);
                }
            } else {
                printf("Error: Invalid unit size.\n");
            }
        } else {
            printf("Error: Invalid input.\n");
        }
    }
}

void quit() {
    if (debug_mode) {
        fprintf(stderr, "quitting\n");
    }
    exit(0);
}

void load_into_memory() {
    if (file_name[0] == '\0') {
        printf("Error: File name is empty.\n");
        return;
    }

    FILE *file = fopen(file_name, "rb");
    if (file == NULL) {
        printf("Error: Failed to open the file.\n");
        return;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        printf("Error: Failed to seek to end.\n");
        fclose(file);
        return;
    }
    long file_size = ftell(file);
    if (fseek(file, 0, SEEK_SET) != 0) {
        printf("Error: Failed to seek to start.\n");
        fclose(file);
        return;
    }

    char input[128];
    int location;
    size_t length;

    printf("Please enter <location> <length>: ");
    if (fgets(input, sizeof(input), stdin) != NULL) {
        if (sscanf(input, "%x %zu", &location, &length) != 2) {
            printf("Error: Invalid input.\n");
            fclose(file);
            return;
        }
    } else {
        fclose(file);
        return;
    }

    if (debug_mode) {
        fprintf(stderr, "Debug: file_name='%s', location=0x%X, length=%zu\n", 
                file_name, location, length);
    }

    size_t bytes_to_read = length * unit_size;
    if (location < 0 || location > file_size || (location + bytes_to_read) > (size_t)file_size) {
        printf("Error: Requested location or length exceeds file size (%ld bytes).\n", file_size);
        fclose(file);
        return;
    }

    if (fseek(file, location, SEEK_SET) != 0) {
        printf("Error: Failed to seek to location 0x%X.\n", location);
        fclose(file);
        return;
    }

    mem_count = fread(mem_buf, unit_size, length, file);
    
    printf("Loaded %zu units into memory\n", mem_count);

    fclose(file);
}

void toggle_display_mode() {
    if (display_mode == 0) {
        display_mode = 1;
        printf("Decimal display flag now on, decimal representation\n");
    } else {
        display_mode = 0;
        printf("Decimal display flag now off, hexadecimal representation\n");
    }
}

void memory_display() {
    char input[128];
    unsigned int addr;
    size_t u;

    printf("Enter address and length\n> ");
    if (fgets(input, sizeof(input), stdin) != NULL) {
        if (sscanf(input, "%x %zu", &addr, &u) != 2) {
            printf("Error: Invalid input.\n");
            return;
        }
    } else {
        return;
    }

    unsigned char* ptr;
    if (addr == 0) {
        ptr = mem_buf;
    } else {
        ptr = (unsigned char*)addr;
    }

    if (display_mode == 0) {
        printf("Hexadecimal\n===========\n");
    } else {
        printf("Decimal\n=======\n");
    }

    for (size_t i = 0; i < u; i++) {
        void* current_unit = ptr + (i * unit_size);
        unsigned int value = 0;

        if (unit_size == 1) {
            value = *(unsigned char*)current_unit;
        } else if (unit_size == 2) {
            value = *(unsigned short*)current_unit;
        } else if (unit_size == 4) {
            value = *(unsigned int*)current_unit;
        }

        if (display_mode == 0) {
            printf(hex_formats[unit_size - 1], value);
        } else {
            printf(dec_formats[unit_size - 1], value);
        }
    }
}

void save_into_file() {
    if (file_name[0] == '\0') {
        printf("Error: File name is empty.\n");
        return;
    }

    FILE *file = fopen(file_name, "r+");
    if (file == NULL) {
        printf("Error: Failed to open the file.\n");
        return;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        printf("Error: Failed to seek to end.\n");
        fclose(file);
        return;
    }
    long file_size = ftell(file);
    if (fseek(file, 0, SEEK_SET) != 0) {
        printf("Error: Failed to seek to start.\n");
        fclose(file);
        return;
    }

    char input[128];
    unsigned int source_address;
    int target_location;
    size_t length;

    printf("Please enter <source_address> <target_location> <length>\n> ");
    if (fgets(input, sizeof(input), stdin) != NULL) {
        if (sscanf(input, "%x %x %zu", &source_address, &target_location, &length) != 3) {
            printf("Error: Invalid input.\n");
            fclose(file);
            return;
        }
    } else {
        fclose(file);
        return;
    }

    if (debug_mode) {
        fprintf(stderr, "Debug: file_name='%s', source_address=0x%X, target_location=%d, length=%zu\n",
                file_name, source_address, target_location, length);
    }

    size_t bytes_to_write = length * unit_size;
    if (target_location < 0 || target_location > file_size || (target_location + bytes_to_write) > (size_t)file_size) {
        printf("Error: Target location or length exceeds file size (%ld bytes).\n", file_size);
        fclose(file);
        return;
    }

    unsigned char* src_ptr;
    if (source_address == 0) {
        src_ptr = mem_buf;
    } else {
        src_ptr = (unsigned char*)source_address;
    }

    if (fseek(file, target_location, SEEK_SET) != 0) {
        printf("Error: Failed to seek to target location.\n");
        fclose(file);
        return;
    }

    size_t units_written = fwrite(src_ptr, unit_size, length, file);

    if (units_written != length) {
        printf("Error: Failed to write all units to file.\n");
    } else {
        printf("Wrote %zu units into file starting from offset %d\n", length, target_location);
    }

    fclose(file);
}

void memory_modify() {
    char input[128];
    int location_signed;
    unsigned int val;

    printf("Please enter <location> <val>\n> ");
    if (fgets(input, sizeof(input), stdin) != NULL) {
        if (sscanf(input, "%x %x", &location_signed, &val) == 2) {
            
            if (debug_mode) {
                fprintf(stderr, "Debug: location=0x%X, val=0x%X\n", (unsigned int)location_signed, val);
            }

            if (location_signed >= 0 && (location_signed + unit_size <= 10000)) {
                unsigned char *ptr = mem_buf + (unsigned int)location_signed;
                if (unit_size == 1) {
                    *(unsigned char*)ptr = (unsigned char)val;
                } else if (unit_size == 2) {
                    *(unsigned short*)ptr = (unsigned short)val;
                } else if (unit_size == 4) {
                    *(unsigned int*)ptr = (unsigned int)val;
                }
            } else {
                printf("Error: Memory access out of bounds.\n");
            }
        } else {
            printf("Error: Invalid input.\n");
        }
    }
}

int main(int argc, char **argv) {
    struct fun_desc menu[] = {
        {"Toggle <D>ebug Mode", 'D', toggle_debug_mode},
        {"Set <F>ile Name", 'F', set_file_name},
        {"Set <U>nit Size", 'U', set_unit_size},
        {"<L>oad Into Memory", 'L', load_into_memory},
        {"<T>oggle Display Mode", 'T', toggle_display_mode},
        {"<M>emory Display", 'M', memory_display},
        {"<S>ave Into File", 'S', save_into_file},
        {"Memory Modif<y>", 'y', memory_modify},
        {"<Q>uit", 'Q', quit},
        {NULL, 0, NULL}
    };

    char buffer[1024];
    int i;

    while (1) {
        if (debug_mode) {
            fprintf(stderr, "unit_size: %d, file_name: '%s', mem_count: %zu\n", 
                    unit_size, file_name, mem_count);
        }

        printf("Choose operation:\n");
        i = 0;
        while (menu[i].name != NULL) {
            printf("%s\n", menu[i].name);
            i++;
        }
        printf("> ");

        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            break;
        }

        char choice = buffer[0];
        int choice_index = -1;

        i = 0;
        while (menu[i].name != NULL) {
            if (choice == menu[i].index) {
                choice_index = i;
                break;
            }
            i++;
        }

        if (choice_index == -1) {
            printf("Operation not supported.\n\n");
        } else {
            menu[choice_index].fun();
        }
        printf("\n");
    }

    return 0;
}