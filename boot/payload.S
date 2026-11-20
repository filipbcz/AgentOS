.section .kernel,"a",@progbits
.balign 8
.global elf_start, elf_end
elf_start:
.incbin "kernel.elf"
elf_end:
.section .initrd,"a",@progbits
.global archive_start, archive_end
archive_start:
.incbin "initramfs.cpio"
archive_end:
.section .note.GNU-stack,"",@progbits
