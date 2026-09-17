rule Armory_BOF_sa_findfiles
{
    meta:
        description = "Compiled Rust BOF: findfiles"
        author = "memN0ps"

    strings:
        $crate = "findfiles" ascii
        $capability = " | directories searched: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
