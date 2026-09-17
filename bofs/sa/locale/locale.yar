rule Armory_BOF_sa_locale
{
    meta:
        description = "Compiled Rust BOF: locale"
        author = "memN0ps"

    strings:
        $crate = "locale" ascii
        $capability = "Error retrieving system locale" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
