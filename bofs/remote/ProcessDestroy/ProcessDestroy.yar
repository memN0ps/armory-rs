rule Armory_BOF_remote_ProcessDestroy
{
    meta:
        description = "Compiled Rust BOF: ProcessDestroy"
        author = "memN0ps"

    strings:
        $crate = "ProcessDestroy" ascii
        $capability = "Successfully closed handle 0x" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
