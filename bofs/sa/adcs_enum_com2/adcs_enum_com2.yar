rule Armory_BOF_sa_adcs_enum_com2
{
    meta:
        description = "Compiled Rust BOF: adcs_enum_com2"
        author = "memN0ps"

    strings:
        $crate = "adcs_enum_com2" ascii
        $capability = "=== ADCS CA Info Enumeration via certutil (T1649) ===" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
