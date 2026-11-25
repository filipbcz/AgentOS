/* Static PIE, zero-based offsets. The signed ELF loader accepts exactly
 * RX, R and RW load segments and one dynamic table. No external symbols,
 * text relocations, executable data or runtime dynamic linker are allowed.
 * The kernel replaces the firmware identity map with these W^X boundaries.
 */
ENTRY(kernel_main)
PHDRS {
  text PT_LOAD FLAGS(5);
  ro PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
  dynamic PT_DYNAMIC FLAGS(6);
}
SECTIONS {
  . = 0;
  kernel_begin = .;
  .text : { *(.text .text.*) } :text
  . = ALIGN(4096);
  kernel_ro = .;
  .rodata : { *(.rodata .rodata.*) } :ro
  .dynsym : { *(.dynsym) } :ro
  .dynstr : { *(.dynstr) } :ro
  .hash : { *(.hash) } :ro
  .gnu.hash : { *(.gnu.hash) } :ro
  .rela.dyn : { *(.rela.dyn) } :ro
  . = ALIGN(4096);
  kernel_rw = .;
  .data : { *(.data .data.*) *(.sdata .sdata.*)
            *(.got .got.*) } :data
  .dynamic : { *(.dynamic) } :data :dynamic
  .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) *(.sbss .sbss.*) } :data
  . = ALIGN(4096);
  kernel_end = .;
  /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
