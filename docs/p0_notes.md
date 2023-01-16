Control flow

1. QEMU **BIOS** (being loaded to 0xFFFF0) load  **pintos bootloader** (i.e. loader.S) into 0x7c00-0x7e00 (512 bytes)
2. loader.S searchs **all partitions on all disks**  for Pintos kernel partition, load it into memory.
3. loader.S get the address of `start()` in `threads/start.S`,     from kernel's ELF file format. Transfer control to it.
4. `start()` will eventually call `pintos_init()`

