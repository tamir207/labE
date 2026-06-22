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
    int f;

    if (num_files == 0) {
        printf("Error: No ELF files are currently open\n");
        return;
    }

    for (f = 0; f < num_files; f++) {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_files[f].map_start;
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)((char *)elf_files[f].map_start + ehdr->e_shoff);
        Elf32_Half shstrndx = ehdr->e_shstrndx;
        char *shstrtab = (char *)elf_files[f].map_start + shdr_table[shstrndx].sh_offset;

        int i;
        int symtab_idx = -1;

        for (i = 0; i < ehdr->e_shnum; i++) {
            if (shdr_table[i].sh_type == SHT_SYMTAB) {
                symtab_idx = i;
                break;
            }
        }

        if (symtab_idx == -1) {
            printf("File %s: no symbol table found\n", elf_files[f].name);
            continue;
        }

        Elf32_Shdr *symtab_shdr = &shdr_table[symtab_idx];
        Elf32_Sym *symtab = (Elf32_Sym *)((char *)elf_files[f].map_start + symtab_shdr->sh_offset);
        int num_symbols = symtab_shdr->sh_size / symtab_shdr->sh_entsize;

        Elf32_Shdr *strtab_shdr = &shdr_table[symtab_shdr->sh_link];
        char *strtab = (char *)elf_files[f].map_start + strtab_shdr->sh_offset;

        if (debug_mode) {
            fprintf(stderr, "File %s: symbol table size = %u bytes, number of symbols = %d\n",
                    elf_files[f].name, symtab_shdr->sh_size, num_symbols);
        }

        printf("File %s symbols:\n", elf_files[f].name);

        for (i = 0; i < num_symbols; i++) {
            Elf32_Sym *sym = &symtab[i];
            Elf32_Word value = sym->st_value;
            Elf32_Half section_index = sym->st_shndx;
            char *section_name;
            const char *symbol_name = strtab + sym->st_name;

            if (section_index < ehdr->e_shnum) {
                section_name = shstrtab + shdr_table[section_index].sh_name;
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
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_files[f].map_start;
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)((char *)elf_files[f].map_start + ehdr->e_shoff);

        int i;
        int num_reloc_sections = 0;
        int reloc_index = 0;

        printf("File %s relocations:\n", elf_files[f].name);

        for (i = 0; i < ehdr->e_shnum; i++) {
            if (shdr_table[i].sh_type == SHT_REL || shdr_table[i].sh_type == SHT_RELA) {
                num_reloc_sections = num_reloc_sections + 1;

                Elf32_Shdr *rel_shdr = &shdr_table[i];

                Elf32_Shdr *symtab_shdr = &shdr_table[rel_shdr->sh_link];
                Elf32_Sym  *symtab = (Elf32_Sym *)((char *)elf_files[f].map_start + symtab_shdr->sh_offset);

                Elf32_Shdr *strtab_shdr = &shdr_table[symtab_shdr->sh_link];
                char *strtab = (char *)elf_files[f].map_start + strtab_shdr->sh_offset;

                int entry_size;
                if (rel_shdr->sh_type == SHT_RELA) {
                    entry_size = sizeof(Elf32_Rela);
                } else {
                    entry_size = sizeof(Elf32_Rel);
                }

                int num_relocs = rel_shdr->sh_size / entry_size;

                if (debug_mode) {
                    fprintf(stderr,
                        "Reloc section size: %u bytes, number of relocations: %d\n", rel_shdr->sh_size, num_relocs);
                }

                int j;
                for (j = 0; j < num_relocs; j++) {
                    Elf32_Addr r_offset;
                    Elf32_Word r_info;

                    if (rel_shdr->sh_type == SHT_RELA) {
                        Elf32_Rela *r = (Elf32_Rela *)((char *)elf_files[f].map_start + rel_shdr->sh_offset + j * entry_size);
                        r_offset = r->r_offset;
                        r_info   = r->r_info;
                    } else {
                        Elf32_Rel *r = (Elf32_Rel *)((char *)elf_files[f].map_start + rel_shdr->sh_offset + j * entry_size);
                        r_offset = r->r_offset;
                        r_info   = r->r_info;
                    }

                    unsigned int sym_idx = ELF32_R_SYM(r_info);
                    unsigned int type    = ELF32_R_TYPE(r_info);

                    Elf32_Sym *sym = &symtab[sym_idx];
                    const char *sym_name = strtab + sym->st_name;

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
                        reloc_index, 
                        r_offset, 
                        sym_name, 
                        type_name);
                    reloc_index++;
                }
            }
        }

        if (num_reloc_sections == 0) {
            printf("No relocations\n");
        }
    }
}

void check_files_for_merge() {
    if (num_files != 2) {
        printf("Error: exactly 2 ELF files must be opened for merge checking\n");
        return;
    }

    Elf32_Ehdr *ehdr1 = (Elf32_Ehdr *)elf_files[0].map_start;
    Elf32_Shdr *shdr_table1 = (Elf32_Shdr *)((char *)elf_files[0].map_start + ehdr1->e_shoff);

    Elf32_Ehdr *ehdr2 = (Elf32_Ehdr *)elf_files[1].map_start;
    Elf32_Shdr *shdr_table2 = (Elf32_Shdr *)((char *)elf_files[1].map_start + ehdr2->e_shoff);

    int i;
    int symtab_idx1 = -1, symtab_count1 = 0;
    int symtab_idx2 = -1, symtab_count2 = 0;

    for (i = 0; i < ehdr1->e_shnum; i++) {
        if (shdr_table1[i].sh_type == SHT_SYMTAB) {
            symtab_count1++;
            if (symtab_idx1 == -1) {
                symtab_idx1 = i;
            }
        }
    }

    for (i = 0; i < ehdr2->e_shnum; i++) {
        if (shdr_table2[i].sh_type == SHT_SYMTAB) {
            symtab_count2++;
            if (symtab_idx2 == -1) {
                symtab_idx2 = i;
            }
        }
    }

    if (symtab_count1 != 1 || symtab_count2 != 1) {
        printf("Feature not supported\n");
        return;
    }

    Elf32_Shdr *symtab_shdr1 = &shdr_table1[symtab_idx1];
    Elf32_Sym *symtab1 = (Elf32_Sym *)((char *)elf_files[0].map_start + symtab_shdr1->sh_offset);
    int num_syms1 = symtab_shdr1->sh_size / symtab_shdr1->sh_entsize;
    Elf32_Shdr *strtab_shdr1 = &shdr_table1[symtab_shdr1->sh_link];
    char *strtab1 = (char *)elf_files[0].map_start + strtab_shdr1->sh_offset;

    Elf32_Shdr *symtab_shdr2 = &shdr_table2[symtab_idx2];
    Elf32_Sym *symtab2 = (Elf32_Sym *)((char *)elf_files[1].map_start + symtab_shdr2->sh_offset);
    int num_syms2 = symtab_shdr2->sh_size / symtab_shdr2->sh_entsize;
    Elf32_Shdr *strtab_shdr2 = &shdr_table2[symtab_shdr2->sh_link];
    char *strtab2 = (char *)elf_files[1].map_start + strtab_shdr2->sh_offset;

    int j;

    for (i = 1; i < num_syms1; i++) {
        Elf32_Sym *sym1 = &symtab1[i];
        const char *name1 = strtab1 + sym1->st_name;

        if (name1[0] == '\0') {
            continue;
        }

        int idx2 = -1;
        for (j = 1; j < num_syms2; j++) {
            const char *name2 = strtab2 + symtab2[j].st_name;
            if (strcmp(name1, name2) == 0) {
                idx2 = j;
                break;
            }
        }

        int defined1 = (sym1->st_shndx != SHN_UNDEF);

        if (!defined1) {
            if (idx2 == -1) {
                printf("Symbol %s undefined\n", name1);
            } else {
                int defined2 = (symtab2[idx2].st_shndx != SHN_UNDEF);
                if (!defined2) {
                    printf("Symbol %s undefined\n", name1);
                }
            }
        } else {
            if (idx2 != -1) {
                int defined2 = (symtab2[idx2].st_shndx != SHN_UNDEF);
                if (defined2) {
                    printf("Symbol %s multiply defined\n", name1);
                }
            }
        }
    }

    for (i = 1; i < num_syms2; i++) {
        Elf32_Sym *sym2 = &symtab2[i];
        const char *name2 = strtab2 + sym2->st_name;

        if (name2[0] == '\0') {
            continue;
        }

        int idx1 = -1;
        for (j = 1; j < num_syms1; j++) {
            const char *name1 = strtab1 + symtab1[j].st_name;
            if (strcmp(name2, name1) == 0) {
                idx1 = j;
                break;
            }
        }

        int defined2 = (sym2->st_shndx != SHN_UNDEF);

        if (!defined2) {
            if (idx1 == -1) {
                printf("Symbol %s undefined\n", name2);
            } else {
                int defined1 = (symtab1[idx1].st_shndx != SHN_UNDEF);
                if (!defined1) {
                    printf("Symbol %s undefined\n", name2);
                }
            }
        } else {
            if (idx1 != -1) {
                int defined1 = (symtab1[idx1].st_shndx != SHN_UNDEF);
                if (defined1) {
                    printf("Symbol %s multiply defined\n", name2);
                }
            }
        }
    }
}

void merge_elf_files() {
    printf("Merge ELF Files: not implemented yet\n");
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