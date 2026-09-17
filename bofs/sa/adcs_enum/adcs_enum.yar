rule Armory_BOF_sa_adcs_enum
{
    meta:
        description = "Compiled Rust BOF: adcs_enum"
        author = "memN0ps"

    strings:
        $crate = "adcs_enum" ascii
        $capability = "No Certificate Authorities found in the domain." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
