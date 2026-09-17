rule Armory_BOF_sa_get_netsession
{
    meta:
        description = "Compiled Rust BOF: get_netsession"
        author = "memN0ps"

    strings:
        $crate = "get_netsession" ascii
        $capability = "Network sessions at " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
