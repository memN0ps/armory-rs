rule Armory_BOF_remote_disableuser
{
    meta:
        description = "Compiled Rust BOF: disableuser"
        author = "memN0ps"

    strings:
        $crate = "disableuser" ascii
        $capability = "Disabling user '" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
