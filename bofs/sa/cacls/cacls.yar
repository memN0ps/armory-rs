rule Armory_BOF_sa_cacls
{
    meta:
        description = "Compiled Rust BOF: cacls"
        author = "memN0ps"

    strings:
        $crate = "cacls" ascii
        $capability = "No DACL found for " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
