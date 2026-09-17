rule Armory_BOF_remote_unexpireuser
{
    meta:
        description = "Compiled Rust BOF: unexpireuser"
        author = "memN0ps"

    strings:
        $crate = "unexpireuser" ascii
        $capability = "Setting password to never expire for user '" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
