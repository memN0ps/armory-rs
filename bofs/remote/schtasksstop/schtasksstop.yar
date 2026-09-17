rule Armory_BOF_remote_schtasksstop
{
    meta:
        description = "Compiled Rust BOF: schtasksstop"
        author = "memN0ps"

    strings:
        $crate = "schtasksstop" ascii
        $capability = "schtasksstop:" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
