SECTIONS {
	. = 0;
	start : { *(start) }
	.text : { *(.text*) }
	.rodata : { *(.rodata*) }
	.data : { *(.data* .bss*) }
	_bss_end = .;
	ASSERT (_bss_end < 0x0a000, "Too much code!")
	stack_svc_end = 0x0b000;
	stack_abt_end = 0x0c000;
	stack_und_end = 0x0d000;
	stack_irq_end = 0x0e000;
	stack_fiq_end = 0x0f000;
	stack_end = 0x10000;
	txring = 0x10000;
	rxring = 0x10400;
	txuart = 0x10800;
	rxuart = 0x10c00;
	devcbuf = 0x11000;
	rxbuf = 0x11800;
	txdata = 0x12000;
	rxdata = 0x14000;
	txtcp = 0x18000;
	rxtcp = 0x1c000;
}
