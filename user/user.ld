ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); abi PT_NOTE FLAGS(4); }
SECTIONS {
    . = 0x8000400000;
    .text : { *(.text*) *(.rodata*) } :text
    .note.agentos ALIGN(4) : { KEEP(*(.note.agentos)) } :text :abi
    . = ALIGN(4096);
    .data : { *(.data*) *(.bss*) } :data
    /DISCARD/ : { *(.note*) *(.comment*) }
}
