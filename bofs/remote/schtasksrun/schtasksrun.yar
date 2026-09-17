rule Armory_BOF_remote_schtasksrun
{
    meta:
        description = "Compiled Rust BOF: schtasksrun"
        author = "memN0ps"

    strings:
        $crate = "schtasksrun" ascii
        $capability = "schtasksrun:" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
