rule Armory_BOF_sa_aisurface
{
    meta:
        description = "Compiled Rust BOF: aisurface"
        author = "memN0ps"

    strings:
        $crate = "aisurface" ascii
        $capability = "Presence only; configuration and session contents are not read." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
