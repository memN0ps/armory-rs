rule Armory_BOF_sa_get_netsession2
{
    meta:
        description = "Compiled Rust BOF: get_netsession2"
        author = "memN0ps"

    strings:
        $crate = "get_netsession2" ascii
        $capability = "\",\"sessions\":[" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
