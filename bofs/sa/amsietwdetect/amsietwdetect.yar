rule Armory_BOF_sa_amsietwdetect
{
    meta:
        description = "Compiled Rust BOF: amsietwdetect"
        author = "memN0ps"

    strings:
        $crate = "amsietwdetect" ascii
        $capability = "AMSI and ETW presence in the current process" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
