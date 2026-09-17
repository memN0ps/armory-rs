rule Armory_BOF_injection_uxsubclassinfo
{
    meta:
        description = "Compiled Rust BOF: uxsubclassinfo"
        author = "memN0ps"

    strings:
        $crate = "uxsubclassinfo" ascii
        $capability = "SUCCESS - uxsubclassinfo injection variant, remote thread created." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
