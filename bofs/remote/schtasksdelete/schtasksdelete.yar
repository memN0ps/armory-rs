rule Armory_BOF_remote_schtasksdelete
{
    meta:
        description = "Compiled Rust BOF: schtasksdelete"
        author = "memN0ps"

    strings:
        $crate = "schtasksdelete" ascii
        $capability = "schtasksdelete:" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
