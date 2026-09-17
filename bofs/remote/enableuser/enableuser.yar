rule Armory_BOF_remote_enableuser
{
    meta:
        description = "Compiled Rust BOF: enableuser"
        author = "memN0ps"

    strings:
        $crate = "enableuser" ascii
        $capability = "Enabling user '" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
