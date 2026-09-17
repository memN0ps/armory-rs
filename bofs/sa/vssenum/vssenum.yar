rule Armory_BOF_sa_vssenum
{
    meta:
        description = "Compiled Rust BOF: vssenum"
        author = "memN0ps"

    strings:
        $crate = "vssenum" ascii
        $capability = "=== Volume Shadow Copy Enumeration ===" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
