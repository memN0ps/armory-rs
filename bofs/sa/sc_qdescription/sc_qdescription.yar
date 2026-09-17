rule Armory_BOF_sa_sc_qdescription
{
    meta:
        description = "Compiled Rust BOF: sc_qdescription"
        author = "memN0ps"

    strings:
        $crate = "sc_qdescription" ascii
        $capability = "DESCRIPTION: (none)" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
