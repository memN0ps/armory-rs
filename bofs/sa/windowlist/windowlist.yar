rule Armory_BOF_sa_windowlist
{
    meta:
        description = "Compiled Rust BOF: windowlist"
        author = "memN0ps"

    strings:
        $crate = "windowlist" ascii
        $capability = "go" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
