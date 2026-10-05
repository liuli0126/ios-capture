// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the conditions in LICENSE are met.

#include "fishhook.h"

#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST "__DATA_CONST"
#endif

struct rebindings_entry {
  struct rebinding *rebindings;
  size_t rebindings_nel;
  struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel) {
  struct rebindings_entry *new_entry = malloc(sizeof(struct rebindings_entry));
  if (!new_entry) {
    return -1;
  }
  new_entry->rebindings = malloc(sizeof(struct rebinding) * nel);
  if (!new_entry->rebindings) {
    free(new_entry);
    return -1;
  }
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
  new_entry->rebindings_nel = nel;
  new_entry->next = *rebindings_head;
  *rebindings_head = new_entry;
  return 0;
}

static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab) {
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);

  for (uint32_t index = 0; index < section->size / sizeof(void *); index++) {
    uint32_t symtab_index = indirect_symbol_indices[index];
    if (symtab_index == INDIRECT_SYMBOL_ABS ||
        symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
      continue;
    }

    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    bool symbol_name_longer_than_one = symbol_name[0] && symbol_name[1];
    struct rebindings_entry *current = rebindings;
    while (current) {
      for (size_t binding_index = 0;
           binding_index < current->rebindings_nel;
           binding_index++) {
        struct rebinding *binding = &current->rebindings[binding_index];
        if (symbol_name_longer_than_one && strcmp(&symbol_name[1], binding->name) == 0) {
          if (binding->replaced && indirect_symbol_bindings[index] != binding->replacement) {
            *binding->replaced = indirect_symbol_bindings[index];
          }

          kern_return_t result = vm_protect(mach_task_self(),
                                             (uintptr_t)indirect_symbol_bindings,
                                             section->size,
                                             false,
                                             VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
          if (result == KERN_SUCCESS) {
            indirect_symbol_bindings[index] = binding->replacement;
          }
          goto symbol_complete;
        }
      }
      current = current->next;
    }
  symbol_complete:;
  }
}

static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
  Dl_info info;
  if (dladdr(header, &info) == 0) {
    return;
  }

  segment_command_t *current_segment = NULL;
  segment_command_t *linkedit_segment = NULL;
  struct symtab_command *symtab_command = NULL;
  struct dysymtab_command *dysymtab_command = NULL;

  uintptr_t cursor = (uintptr_t)header + sizeof(mach_header_t);
  for (uint32_t index = 0; index < header->ncmds; index++, cursor += current_segment->cmdsize) {
    current_segment = (segment_command_t *)cursor;
    if (current_segment->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(current_segment->segname, SEG_LINKEDIT) == 0) {
        linkedit_segment = current_segment;
      }
    } else if (current_segment->cmd == LC_SYMTAB) {
      symtab_command = (struct symtab_command *)current_segment;
    } else if (current_segment->cmd == LC_DYSYMTAB) {
      dysymtab_command = (struct dysymtab_command *)current_segment;
    }
  }

  if (!symtab_command || !dysymtab_command || !linkedit_segment ||
      !dysymtab_command->nindirectsyms) {
    return;
  }

  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_command->symoff);
  char *strtab = (char *)(linkedit_base + symtab_command->stroff);
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_command->indirectsymoff);

  cursor = (uintptr_t)header + sizeof(mach_header_t);
  for (uint32_t index = 0; index < header->ncmds; index++, cursor += current_segment->cmdsize) {
    current_segment = (segment_command_t *)cursor;
    if (current_segment->cmd != LC_SEGMENT_ARCH_DEPENDENT ||
        (strcmp(current_segment->segname, SEG_DATA) != 0 &&
         strcmp(current_segment->segname, SEG_DATA_CONST) != 0)) {
      continue;
    }

    for (uint32_t section_index = 0;
         section_index < current_segment->nsects;
         section_index++) {
      section_t *section = (section_t *)(cursor + sizeof(segment_command_t)) + section_index;
      uint32_t section_type = section->flags & SECTION_TYPE;
      if (section_type == S_LAZY_SYMBOL_POINTERS ||
          section_type == S_NON_LAZY_SYMBOL_POINTERS) {
        perform_rebinding_with_section(rebindings,
                                       section,
                                       slide,
                                       symtab,
                                       strtab,
                                       indirect_symtab);
      }
    }
  }
}

static void rebind_symbols_for_added_image(const struct mach_header *header,
                                           intptr_t slide) {
  rebind_symbols_for_image(_rebindings_head, header, slide);
}

int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct rebinding rebindings[],
                         size_t rebindings_nel) {
  struct rebindings_entry *head = NULL;
  int result = prepend_rebindings(&head, rebindings, rebindings_nel);
  rebind_symbols_for_image(head, (const struct mach_header *)header, slide);
  if (head) {
    free(head->rebindings);
  }
  free(head);
  return result;
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
  int result = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
  if (result < 0) {
    return result;
  }

  if (!_rebindings_head->next) {
    _dyld_register_func_for_add_image(rebind_symbols_for_added_image);
  } else {
    uint32_t image_count = _dyld_image_count();
    for (uint32_t index = 0; index < image_count; index++) {
      rebind_symbols_for_added_image(_dyld_get_image_header(index),
                                     _dyld_get_image_vmaddr_slide(index));
    }
  }
  return result;
}
