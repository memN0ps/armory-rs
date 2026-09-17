rule Armory_BOF_sa_winver
{
    meta:
        description = "Compiled Rust BOF: winver"
        author = "memN0ps"

    strings:
        $crate = "winver" ascii
        $capability = "Registry product label: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
