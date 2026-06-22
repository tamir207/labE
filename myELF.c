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

int is_valid_elf(Elf32_Ehdr *elf_header) {
    if (elf_header->e_ident[EI_MAG0] != ELFMAG0 ||
        elf_header->e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header->e_ident[EI_MAG2] != ELFMAG2 ||
        elf_header->e_ident[EI_MAG3] != ELFMAG3) {
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
    Elf32_Ehdr *elf_header;

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

    elf_header = (Elf32_Ehdr *)map_start;

    if (!is_valid_elf(elf_header)) {
        printf("Error: Not a valid ELF file\n");
        munmap(map_start, file_size);
        close(fd);
        return;
    }

    printf("Magic number (bytes 1-3):           %c%c%c\n", elf_header->e_ident[1], elf_header->e_ident[2], elf_header->e_ident[3]);
    printf("Data encoding:                      %s\n", get_encoding_desc(elf_header->e_ident[EI_DATA]));
    printf("Entry point (hex):                  0x%x\n", elf_header->e_entry);
    printf("Section header table offset:        %u (0x%x)\n", elf_header->e_shoff, elf_header->e_shoff);
    printf("Number of section header entries:   %u\n", elf_header->e_shnum);
    printf("Section header entry size:          %u bytes\n", elf_header->e_shentsize);
    printf("Program header table offset:        %u (0x%x)\n", elf_header->e_phoff, elf_header->e_phoff);
    printf("Number of program header entries:   %u\n", elf_header->e_phnum);
    printf("Program header entry size:          %u bytes\n", elf_header->e_phentsize);

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
        Elf32_Ehdr *elf_header = (Elf32_Ehdr *)elf_files[f].map_start;
        Elf32_Shdr *section_headers = (Elf32_Shdr *)((char *)elf_files[f].map_start + elf_header->e_shoff);
        Elf32_Half section_names_index = elf_header->e_shstrndx;
        char *section_names = (char *)elf_files[f].map_start + section_headers[section_names_index].sh_offset;

        if (debug_mode) {
            fprintf(stderr, "section_names_index: %u\n", section_names_index);
        }

        printf("File %s sections:\n", elf_files[f].name);

        for (i = 0; i < elf_header->e_shnum; i++) {
            char *name = section_names + section_headers[i].sh_name;

            if (debug_mode) {
                fprintf(stderr, "section[%d] sh_name offset: %u\n", i, section_headers[i].sh_name);
            }

            printf("[%2d] %-18s %08x %08x %08x %u\n",
                   i,
                   name,
                   section_headers[i].sh_addr,
                   section_headers[i].sh_offset,
                   section_headers[i].sh_size,
                   section_headers[i].sh_type);
        }
    }
}

void print_symbols() {
    int f;

    if (num_files == 0) {
        printf("Error: No ELF files are currently open\n");
        return;
    }

    for (f = 0; f < num_files; f++) {
        Elf32_Ehdr *elf_header = (Elf32_Ehdr *)elf_files[f].map_start;
        Elf32_Shdr *section_headers = (Elf32_Shdr *)((char *)elf_files[f].map_start + elf_header->e_shoff);
        Elf32_Half section_names_index = elf_header->e_shstrndx;
        char *section_names = (char *)elf_files[f].map_start + section_headers[section_names_index].sh_offset;

        int i;
        int symbol_table_index = -1;

        for (i = 0; i < elf_header->e_shnum; i++) {
            if (section_headers[i].sh_type == SHT_SYMTAB) {
                symbol_table_index = i;
                break;
            }
        }

        if (symbol_table_index == -1) {
            printf("File %s: no symbol table found\n", elf_files[f].name);
            continue;
        }

        Elf32_Shdr *symbol_table_header = &section_headers[symbol_table_index];
        Elf32_Sym *symbol_table = (Elf32_Sym *)((char *)elf_files[f].map_start + symbol_table_header->sh_offset);
        int num_symbols = symbol_table_header->sh_size / symbol_table_header->sh_entsize;

        Elf32_Shdr *string_table_header = &section_headers[symbol_table_header->sh_link];
        char *string_table = (char *)elf_files[f].map_start + string_table_header->sh_offset;

        if (debug_mode) {
            fprintf(stderr, "File %s: symbol table size = %u bytes, number of symbols = %d\n",
                    elf_files[f].name, symbol_table_header->sh_size, num_symbols);
        }

        printf("File %s symbols:\n", elf_files[f].name);

        for (i = 0; i < num_symbols; i++) {
            Elf32_Sym *symbol = &symbol_table[i];
            Elf32_Word value = symbol->st_value;
            Elf32_Half section_index = symbol->st_shndx;
            char *section_name;
            const char *symbol_name = string_table + symbol->st_name;

            if (section_index < elf_header->e_shnum) {
                section_name = section_names + section_headers[section_index].sh_name;
            } else {
                section_name = "";
            }

            printf("[%2d] %08x %4u %-15s %s\n",
                   i,
                   value,
                   section_index,
                   section_name,
                   symbol_name);
        }
    }
}

void print_relocations() {
    int f;

    if (num_files == 0) {
        printf("Error: No ELF files are currently open\n");
        return;
    }

    for (f = 0; f < num_files; f++) {
        Elf32_Ehdr *elf_header = (Elf32_Ehdr *)elf_files[f].map_start;
        Elf32_Shdr *section_headers = (Elf32_Shdr *)((char *)elf_files[f].map_start + elf_header->e_shoff);

        int i;
        int reloc_sections_count = 0;
        int reloc_counter = 0;

        printf("File %s relocations:\n", elf_files[f].name);

        for (i = 0; i < elf_header->e_shnum; i++) {
            if (section_headers[i].sh_type == SHT_REL || section_headers[i].sh_type == SHT_RELA) {
                reloc_sections_count = reloc_sections_count + 1;

                Elf32_Shdr *reloc_header = &section_headers[i];

                Elf32_Shdr *symbol_table_header = &section_headers[reloc_header->sh_link];
                Elf32_Sym  *symbol_table = (Elf32_Sym *)((char *)elf_files[f].map_start + symbol_table_header->sh_offset);

                Elf32_Shdr *string_table_header = &section_headers[symbol_table_header->sh_link];
                char *string_table = (char *)elf_files[f].map_start + string_table_header->sh_offset;

                int entry_size;
                if (reloc_header->sh_type == SHT_RELA) {
                    entry_size = sizeof(Elf32_Rela);
                } else {
                    entry_size = sizeof(Elf32_Rel);
                }

                int relocs_count = reloc_header->sh_size / entry_size;

                if (debug_mode) {
                    fprintf(stderr,
                        "Reloc section size: %u bytes, number of relocations: %d\n", reloc_header->sh_size, relocs_count);
                }

                int j;
                for (j = 0; j < relocs_count; j++) {
                    Elf32_Addr reloc_offset;
                    Elf32_Word reloc_info;

                    if (reloc_header->sh_type == SHT_RELA) {
                        Elf32_Rela *reloc_entry = (Elf32_Rela *)((char *)elf_files[f].map_start + reloc_header->sh_offset + j * entry_size);
                        reloc_offset = reloc_entry->r_offset;
                        reloc_info   = reloc_entry->r_info;
                    } else {
                        Elf32_Rel *reloc_entry = (Elf32_Rel *)((char *)elf_files[f].map_start + reloc_header->sh_offset + j * entry_size);
                        reloc_offset = reloc_entry->r_offset;
                        reloc_info   = reloc_entry->r_info;
                    }

                    unsigned int symbol_index = ELF32_R_SYM(reloc_info);
                    unsigned int type    = ELF32_R_TYPE(reloc_info);

                    Elf32_Sym *symbol = &symbol_table[symbol_index];
                    const char *symbol_name = string_table + symbol->st_name;

                    const char *type_name;
                    if (type == R_386_NONE) 
                        type_name = "R_386_NONE";
                    else if (type == R_386_32) 
                        type_name = "R_386_32";
                    else if (type == R_386_PC32) 
                        type_name = "R_386_PC32";
                    else if (type == R_386_GOT32) 
                        type_name = "R_386_GOT32";
                    else if (type == R_386_PLT32) 
                        type_name = "R_386_PLT32";
                    else if (type == R_386_COPY) 
                        type_name = "R_386_COPY";
                    else if (type == R_386_GLOB_DAT) 
                        type_name = "R_386_GLOB_DAT";
                    else if (type == R_386_JMP_SLOT) 
                        type_name = "R_386_JUMP_SLOT";
                    else if (type == R_386_RELATIVE) 
                        type_name = "R_386_RELATIVE";
                    else if (type == R_386_GOTOFF) 
                        type_name = "R_386_GOTOFF";
                    else if (type == R_386_GOTPC) 
                        type_name = "R_386_GOTPC";
                    else type_name = "UNKNOWN";

                    printf("[%2d] %08x %-20s %s\n", 
                        reloc_counter, 
                        reloc_offset, 
                        symbol_name, 
                        type_name);
                    reloc_counter++;
                }
            }
        }

        if (reloc_sections_count == 0) {
            printf("No relocations\n");
        }
    }
}

void check_files_for_merge() {
    if (num_files != 2) {
        printf("Error: exactly 2 ELF files must be opened for merge checking\n");
        return;
    }

    Elf32_Ehdr *elf_header1 = (Elf32_Ehdr *)elf_files[0].map_start;
    Elf32_Shdr *section_headers1 = (Elf32_Shdr *)((char *)elf_files[0].map_start + elf_header1->e_shoff);

    Elf32_Ehdr *elf_header2 = (Elf32_Ehdr *)elf_files[1].map_start;
    Elf32_Shdr *section_headers2 = (Elf32_Shdr *)((char *)elf_files[1].map_start + elf_header2->e_shoff);

    int i;
    int symbol_table_index1 = -1, symbol_tables_found1 = 0;
    int symbol_table_index2 = -1, symbol_tables_found2 = 0;

    for (i = 0; i < elf_header1->e_shnum; i++) {
        if (section_headers1[i].sh_type == SHT_SYMTAB) {
            symbol_tables_found1++;
            if (symbol_table_index1 == -1) {
                symbol_table_index1 = i;
            }
        }
    }

    for (i = 0; i < elf_header2->e_shnum; i++) {
        if (section_headers2[i].sh_type == SHT_SYMTAB) {
            symbol_tables_found2++;
            if (symbol_table_index2 == -1) {
                symbol_table_index2 = i;
            }
        }
    }

    if (symbol_tables_found1 != 1 || symbol_tables_found2 != 1) {
        printf("Feature not supported\n");
        return;
    }

    Elf32_Shdr *symbol_table_header1 = &section_headers1[symbol_table_index1];
    Elf32_Sym *symbol_table1 = (Elf32_Sym *)((char *)elf_files[0].map_start + symbol_table_header1->sh_offset);
    int symbols_count1 = symbol_table_header1->sh_size / symbol_table_header1->sh_entsize;
    Elf32_Shdr *string_table_header1 = &section_headers1[symbol_table_header1->sh_link];
    char *string_table1 = (char *)elf_files[0].map_start + string_table_header1->sh_offset;

    Elf32_Shdr *symbol_table_header2 = &section_headers2[symbol_table_index2];
    Elf32_Sym *symbol_table2 = (Elf32_Sym *)((char *)elf_files[1].map_start + symbol_table_header2->sh_offset);
    int symbols_count2 = symbol_table_header2->sh_size / symbol_table_header2->sh_entsize;
    Elf32_Shdr *string_table_header2 = &section_headers2[symbol_table_header2->sh_link];
    char *string_table2 = (char *)elf_files[1].map_start + string_table_header2->sh_offset;

    int j;

    for (i = 1; i < symbols_count1; i++) {
        Elf32_Sym *symbol1 = &symbol_table1[i];
        const char *name1 = string_table1 + symbol1->st_name;

        if (name1[0] == '\0') {
            continue;
        }

        int found_index2 = -1;
        for (j = 1; j < symbols_count2; j++) {
            const char *name2 = string_table2 + symbol_table2[j].st_name;
            if (strcmp(name1, name2) == 0) {
                found_index2 = j;
                break;
            }
        }

        int defined1 = (symbol1->st_shndx != SHN_UNDEF);

        if (!defined1) {
            if (found_index2 == -1) {
                printf("Symbol %s undefined\n", name1);
            } else {
                int defined2 = (symbol_table2[found_index2].st_shndx != SHN_UNDEF);
                if (!defined2) {
                    printf("Symbol %s undefined\n", name1);
                }
            }
        } else {
            if (found_index2 != -1) {
                int defined2 = (symbol_table2[found_index2].st_shndx != SHN_UNDEF);
                if (defined2) {
                    printf("Symbol %s multiply defined\n", name1);
                }
            }
        }
    }

    for (i = 1; i < symbols_count2; i++) {
        Elf32_Sym *symbol2 = &symbol_table2[i];
        const char *name2 = string_table2 + symbol2->st_name;

        if (name2[0] == '\0') {
            continue;
        }

        int found_index1 = -1;
        for (j = 1; j < symbols_count1; j++) {
            const char *name1 = string_table1 + symbol_table1[j].st_name;
            if (strcmp(name2, name1) == 0) {
                found_index1 = j;
                break;
            }
        }

        int defined2 = (symbol2->st_shndx != SHN_UNDEF);

        if (!defined2) {
            if (found_index1 == -1) {
                printf("Symbol %s undefined\n", name2);
            } else {
                int defined1 = (symbol_table1[found_index1].st_shndx != SHN_UNDEF);
                if (!defined1) {
                    printf("Symbol %s undefined\n", name2);
                }
            }
        } else {
            if (found_index1 != -1) {
                int defined1 = (symbol_table1[found_index1].st_shndx != SHN_UNDEF);
                if (defined1) {
                    printf("Symbol %s multiply defined\n", name2);
                }
            }
        }
    }
}

void merge_elf_files() {
    if (num_files != 2) {
        printf("Error: exactly 2 ELF files must be opened for merge\n");
        return;
    }

    Elf32_Ehdr *elf_header1 = (Elf32_Ehdr *)elf_files[0].map_start;
    Elf32_Shdr *section_headers1 = (Elf32_Shdr *)((char *)elf_files[0].map_start + elf_header1->e_shoff);
    char *section_names1 = (char *)elf_files[0].map_start + section_headers1[elf_header1->e_shstrndx].sh_offset;

    Elf32_Ehdr *elf_header2 = (Elf32_Ehdr *)elf_files[1].map_start;
    Elf32_Shdr *section_headers2 = (Elf32_Shdr *)((char *)elf_files[1].map_start + elf_header2->e_shoff);
    char *section_names2 = (char *)elf_files[1].map_start + section_headers2[elf_header2->e_shstrndx].sh_offset;

    int out_fd = open("out.ro", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd == -1) {
        printf("Error: Failed to create out.ro\n");
        return;
    }

    Elf32_Ehdr out_elf_header = *elf_header1;

    int section_count = elf_header1->e_shnum;
    Elf32_Shdr *out_section_headers = (Elf32_Shdr *)malloc(section_count * sizeof(Elf32_Shdr));
    if (out_section_headers == NULL) {
        printf("Error: malloc failed\n");
        close(out_fd);
        return;
    }
    memcpy(out_section_headers, section_headers1, section_count * sizeof(Elf32_Shdr));

    write(out_fd, &out_elf_header, sizeof(Elf32_Ehdr));
    unsigned int current_offset = sizeof(Elf32_Ehdr);

    int i, j;
    for (i = 0; i < section_count; i++) {
        char *section_name = section_names1 + section_headers1[i].sh_name;

        unsigned int new_offset = current_offset;
        unsigned int new_size   = section_headers1[i].sh_size;

        int mergeable = (strcmp(section_name, ".text")   == 0 || strcmp(section_name, ".data")   == 0 || strcmp(section_name, ".rodata") == 0);

        char *content1 = (char *)elf_files[0].map_start + section_headers1[i].sh_offset;
        write(out_fd, content1, section_headers1[i].sh_size);
        current_offset += section_headers1[i].sh_size;

        if (mergeable) {
            int found = -1;
            for (j = 0; j < elf_header2->e_shnum; j++) {
                char *name2 = section_names2 + section_headers2[j].sh_name;
                if (strcmp(name2, section_name) == 0) {
                    found = j;
                    break;
                }
            }
            if (found != -1) {
                char *content2 = (char *)elf_files[1].map_start + section_headers2[found].sh_offset;
                write(out_fd, content2, section_headers2[found].sh_size);
                current_offset += section_headers2[found].sh_size;
                new_size   += section_headers2[found].sh_size;
            }
        }

        out_section_headers[i].sh_offset = new_offset;
        out_section_headers[i].sh_size   = new_size;
    }

    unsigned int section_headers_offset = current_offset;
    write(out_fd, out_section_headers, section_count * sizeof(Elf32_Shdr));

    out_elf_header.e_shoff = section_headers_offset;
    lseek(out_fd, 0, SEEK_SET);
    write(out_fd, &out_elf_header, sizeof(Elf32_Ehdr));

    free(out_section_headers);
    close(out_fd);
}

void quit() {
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
        int selected_index = -1;

        i = 0;
        while (menu[i].name != NULL) {
            if (choice == menu[i].index) {
                selected_index = i;
                break;
            }
            i++;
        }

        if (selected_index == -1) {
            printf("Operation not supported.\n\n");
        } else {
            menu[selected_index].fun();
        }
        printf("\n");
    }

    return 0;
}