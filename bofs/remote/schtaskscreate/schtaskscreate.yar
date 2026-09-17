rule Armory_BOF_remote_schtaskscreate
{
    meta:
        description = "Compiled Rust BOF: schtaskscreate"
        author = "memN0ps"

    strings:
        $crate = "schtaskscreate" ascii
        $capability = "schtaskscreate:" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
