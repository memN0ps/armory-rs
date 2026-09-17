rule Armory_BOF_remote_shutdown
{
    meta:
        description = "Compiled Rust BOF: shutdown"
        author = "memN0ps"

    strings:
        $crate = "shutdown" ascii
        $capability = "Shutdown privilege enabled." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
