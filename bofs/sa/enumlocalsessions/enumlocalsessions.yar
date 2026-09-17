rule Armory_BOF_sa_enumlocalsessions
{
    meta:
        description = "Compiled Rust BOF: enumlocalsessions"
        author = "memN0ps"

    strings:
        $crate = "enumlocalsessions" ascii
        $capability = "Total active/disconnected sessions: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
