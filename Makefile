all: main.elf BOOT.BIN

main.elf: main.c main.lds
	arm-none-eabi-gcc main.c -o main.elf -ffreestanding -nostdlib -O2 -Wl,-T,main.lds  -march=armv7-a

main.bin: main.elf
	arm-none-eabi-objcopy main.elf -O binary main.bin

BOOT.BIN: main.bin mkboot.py
	python mkboot.py
