#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>

char debug_mode = 0;

#define MAX_FILES 2

typedef struct {
    char name[128];
    int fd;
    void *map_start;
    int file_size;
} ELFFile;

ELFFile elf_files[MAX_FILES];
int num_files = 0;

void toggle_debug_mode();
void examine_elf_file();
void print_section_names();
void print_symbols();
void print_relocations();
void check_files_for_merge();
void merge_elf_files();
void quit();

struct fun_desc {
    char *name;
    char index;
    void (*fun)();
};

void toggle_debug_mode() {
    if (debug_mode == 0) {
        debug_mode = 1;
        fprintf(stderr, "Debug flag now on\n");
    } else {
        debug_mode = 0;
        fprintf(stderr, "Debug flag now off\n");
    }
}

int is_valid_elf(Elf32_Ehdr *ehdr) {
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        return 0;
    }
    return 1;
}

const char* get_encoding_desc(unsigned char encoding) {
    if (encoding == ELFDATA2LSB) {
        return "2's complement, little endian";
    } else if (encoding == ELFDATA2MSB) {
        return "2's complement, big endian";
    } else {
        return "Unknown";
    }
}

void examine_elf_file() {
    char filename[128];
    int fd;
    void *map_start;
    int file_size;
    Elf32_Ehdr *ehdr;

    if (num_files >= MAX_FILES) {
        printf("Error: Maximum %d files can be open at once\n", MAX_FILES);
        return;
    }

    printf("Enter ELF file name: ");
    if (fgets(filename, sizeof(filename), stdin) == NULL) {
        printf("Error reading filename\n");
        return;
    }
    filename[strcspn(filename, "\n")] = 0;

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        printf("Error: Failed to open file '%s'\n", filename);
        return;
    }

    if (lseek(fd, 0, SEEK_END) == -1) {
        printf("Error: Failed to seek to end.\n");
        close(fd);
        return;
    }
    file_size = lseek(fd, 0, SEEK_CUR);
    if (lseek(fd, 0, SEEK_SET) == -1) {
        printf("Error: Failed to seek to start.\n");
        close(fd);
        return;
    }

    map_start = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_start == MAP_FAILED) {
        printf("Error: Failed to map file\n");
        close(fd);
        return;
    }

    ehdr = (Elf32_Ehdr *)map_start;

    if (!is_valid_elf(ehdr)) {
        printf("Error: Not a valid ELF file\n");
        munmap(map_start, file_size);
        close(fd);
        return;
    }

    printf("Magic number (bytes 1-3):           %c%c%c\n", ehdr->e_ident[1], ehdr->e_ident[2], ehdr->e_ident[3]);
    printf("Data encoding:                      %s\n", get_encoding_desc(ehdr->e_ident[EI_DATA]));
    printf("Entry point (hex):                  0x%x\n", ehdr->e_entry);
    printf("Section header table offset:        %u (0x%x)\n", ehdr->e_shoff, ehdr->e_shoff);
    printf("Number of section header entries:   %u\n", ehdr->e_shnum);
    printf("Section header entry size:          %u bytes\n", ehdr->e_shentsize);
    printf("Program header table offset:        %u (0x%x)\n", ehdr->e_phoff, ehdr->e_phoff);
    printf("Number of program header entries:   %u\n", ehdr->e_phnum);
    printf("Program header entry size:          %u bytes\n", ehdr->e_phentsize);

    strcpy(elf_files[num_files].name, filename);
    elf_files[num_files].fd = fd;
    elf_files[num_files].map_start = map_start;
    elf_files[num_files].file_size = file_size;
    num_files++;
}

void print_section_names() {
    int f, i;

    if (num_files == 0) {
        printf("Error: No ELF files are currently open\n");
        return;
    }

    for (f = 0; f < num_files; f++) {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_files[f].map_start;
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)((char *)elf_files[f].map_start + ehdr->e_shoff);
        Elf32_Half shstrndx = ehdr->e_shstrndx;
        char *shstrtab = (char *)elf_files[f].map_start + shdr_table[shstrndx].sh_offset;

        if (debug_mode) {
            fprintf(stderr, "shstrndx: %u\n", shstrndx);
        }

        printf("File %s sections:\n", elf_files[f].name);

        for (i = 0; i < ehdr->e_shnum; i++) {
            char *name = shstrtab + shdr_table[i].sh_name;

            if (debug_mode) {
                fprintf(stderr, "section[%d] sh_name offset: %u\n", i, shdr_table[i].sh_name);
            }

            printf("[%2d] %-18s %08x %08x %08x %u\n",
                   i,
                   name,
                   shdr_table[i].sh_addr,
                   shdr_table[i].sh_offset,
                   shdr_table[i].sh_size,
                   shdr_table[i].sh_type);
        }
    }
}

void print_symbols() {
    printf("Print Symbols: not implemented yet\n");
}

void print_relocations() {
    printf("Print Relocations: not implemented yet\n");
}

void check_files_for_merge() {
    printf("Check Files for Merge: not implemented yet\n");
}

void merge_elf_files() {
    printf("Merge ELF Files: not implemented yet\n");
}

void quit() {
    if (debug_mode) {
        fprintf(stderr, "quitting\n");
    }

    for (int i = 0; i < num_files; i++) {
        if (elf_files[i].map_start != NULL) {
            munmap(elf_files[i].map_start, elf_files[i].file_size);
        }
        if (elf_files[i].fd != -1) {
            close(elf_files[i].fd);
        }
    }

    exit(0);
}

int main(int argc, char **argv) {
    struct fun_desc menu[] = {
        {"Toggle <D>ebug Mode", 'D', toggle_debug_mode},
        {"Examine ELF <F>ile", 'F', examine_elf_file},
        {"Print Section <N>ames", 'N', print_section_names},
        {"Print <S>ymbols", 'S', print_symbols},
        {"Print <R>elocations", 'R', print_relocations},
        {"<C>heck Files for Merge", 'C', check_files_for_merge},
        {"<M>erge ELF Files", 'M', merge_elf_files},
        {"<Q>uit", 'Q', quit},
        {NULL, 0, NULL}
    };

    char buffer[1024];
    int i;

    while (1) {
        if (debug_mode) {
            fprintf(stderr, "num_files: %d\n", num_files);
        }

        printf("Choose action:\n");
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