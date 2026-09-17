rule Armory_BOF_sa_clipboardgrab
{
    meta:
        description = "Compiled Rust BOF: clipboardgrab"
        author = "memN0ps"

    strings:
        $crate = "clipboardgrab" ascii
        $capability = "Warning: clipboard output may contain sensitive values." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
