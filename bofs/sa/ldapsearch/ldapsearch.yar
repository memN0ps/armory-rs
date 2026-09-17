rule Armory_BOF_sa_ldapsearch
{
    meta:
        description = "Compiled Rust BOF: ldapsearch"
        author = "memN0ps"

    strings:
        $crate = "ldapsearch" ascii
        $capability = "Auto-detected DC: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
