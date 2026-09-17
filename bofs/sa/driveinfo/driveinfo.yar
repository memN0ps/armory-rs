rule Armory_BOF_sa_driveinfo
{
    meta:
        description = "Compiled Rust BOF: driveinfo"
        author = "memN0ps"

    strings:
        $crate = "driveinfo" ascii
        $capability = "volume:      unavailable (0x" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
