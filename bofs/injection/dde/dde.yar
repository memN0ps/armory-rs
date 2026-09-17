rule Armory_BOF_injection_dde
{
    meta:
        description = "Compiled Rust BOF: dde"
        author = "memN0ps"

    strings:
        $crate = "dde" ascii
        $capability = "SUCCESS: Shellcode injected via DDE protocol-based injection" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
