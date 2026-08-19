ENTRY(_exploit)

MEMORY
{
  RAM (rx) : ORIGIN = 0xFEBF0000, LENGTH = 0xFD0
}

SECTIONS
{
  .text.entry : ALIGN(2) { KEEP(*(.text.entry)) } > RAM
  .text       : ALIGN(2) { *(.text .text.*) } > RAM
  .rodata     : ALIGN(4) { *(.rodata .rodata.*) } > RAM
  /DISCARD/   : { *(.comment) *(.note*) *(.eh_frame*) *(.debug*) *(.data*) *(.bss*) }
}
