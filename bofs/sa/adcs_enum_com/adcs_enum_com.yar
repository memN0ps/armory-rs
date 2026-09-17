rule Armory_BOF_sa_adcs_enum_com
{
    meta:
        description = "Compiled Rust BOF: adcs_enum_com"
        author = "memN0ps"

    strings:
        $crate = "adcs_enum_com" ascii
        $capability = "=== ADCS CA Enumeration via ICertConfig2 COM (T1649) ===" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
