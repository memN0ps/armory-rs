rule Armory_BOF_sa_sc_query
{
    meta:
        description = "Compiled Rust BOF: sc_query"
        author = "memN0ps"

    strings:
        $crate = "sc_query" ascii
        $capability = "Total services: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
