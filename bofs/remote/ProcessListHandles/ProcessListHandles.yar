rule Armory_BOF_remote_ProcessListHandles
{
    meta:
        description = "Compiled Rust BOF: ProcessListHandles"
        author = "memN0ps"

    strings:
        $crate = "ProcessListHandles" ascii
        $capability = "Listing handles for PID: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
