rule Armory_BOF_sa_nonpagedldapsearch
{
    meta:
        description = "Compiled Rust BOF: nonpagedldapsearch"
        author = "memN0ps"

    strings:
        $crate = "nonpagedldapsearch" ascii
        $capability = "Auto-detected DC: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
