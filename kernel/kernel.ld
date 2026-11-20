ENTRY(kernel_main)
PHDRS { code PT_LOAD FLAGS(5); }
SECTIONS {
  . = 0x02000000;
  kernel_begin = .;
  .text : { *(.text .text.*) } :code
  . = ALIGN(4096);
  kernel_ro = .;
  .rodata : { *(.rodata .rodata.*) *(.data.rel.ro*) *(.got*) } :code
  kernel_end = .;
  /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
