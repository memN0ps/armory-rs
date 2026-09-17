rule Armory_BOF_sa_useridletime
{
    meta:
        description = "Compiled Rust BOF: useridletime"
        author = "memN0ps"

    strings:
        $crate = "useridletime" ascii
        $capability = "Current User idle time: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
