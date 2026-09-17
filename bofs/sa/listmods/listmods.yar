rule Armory_BOF_sa_listmods
{
    meta:
        description = "Compiled Rust BOF: listmods"
        author = "memN0ps"

    strings:
        $crate = "listmods" ascii
        $capability = "Listing modules for PID: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
