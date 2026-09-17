rule Armory_BOF_remote_sc_failure
{
    meta:
        description = "Compiled Rust BOF: sc_failure"
        author = "memN0ps"

    strings:
        $crate = "sc_failure" ascii
        $capability = "action2:      type=" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
