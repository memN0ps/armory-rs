rule Armory_BOF_sa_wevtlogons
{
    meta:
        description = "Compiled Rust BOF: wevtlogons"
        author = "memN0ps"

    strings:
        $crate = "wevtlogons" ascii
        $capability = "Recent Windows Security logon events | limit=" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
