rule Armory_BOF_injection_conhost
{
    meta:
        description = "Compiled Rust BOF: conhost"
        author = "memN0ps"

    strings:
        $crate = "conhost" ascii
        $capability = "SUCCESS: Shellcode injected via Console Host (conhost.exe) injection" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
