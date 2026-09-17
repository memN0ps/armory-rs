rule Armory_BOF_remote_procdump
{
    meta:
        description = "Compiled Rust BOF: procdump"
        author = "memN0ps"

    strings:
        $crate = "procdump" ascii
        $capability = "Successfully dumped process " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
