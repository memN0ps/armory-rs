rule Armory_BOF_remote_adduser
{
    meta:
        description = "Compiled Rust BOF: adduser"
        author = "memN0ps"

    strings:
        $crate = "adduser" ascii
        $capability = "Successfully added user '" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
