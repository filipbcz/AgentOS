/* The loader accepts a single fixed-address PT_LOAD (PF_R|PF_X).
 * It copies filesz, zeroes memsz-filesz, then the kernel replaces firmware
 * mappings with section-specific W^X permissions. All allocated sections,
 * including mutable globals from later development, MUST precede kernel_end.
 * Page alignment prevents writable and executable aliases on one page.
 */
ENTRY(kernel_main)
PHDRS { code PT_LOAD FLAGS(5); }
SECTIONS {
  . = 0x02000000;
  kernel_begin = .;
  .text : { *(.text .text.*) } :code
  . = ALIGN(4096);
  kernel_ro = .;
  .rodata : { *(.rodata .rodata.*) } :code
  . = ALIGN(4096);
  kernel_rw = .;
  .data : { *(.data .data.*) *(.sdata .sdata.*)
            *(.data.rel.ro .data.rel.ro.*) *(.got .got.*) } :code
  .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) *(.sbss .sbss.*) } :code
  . = ALIGN(4096);
  kernel_end = .;
  /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
