rule Armory_BOF_remote_shspawnas
{
    meta:
        description = "Compiled Rust BOF: shspawnas"
        author = "memN0ps"

    strings:
        $crate = "shspawnas" ascii
        $capability = "Process spawned successfully (PID: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
