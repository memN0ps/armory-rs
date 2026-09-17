rule Armory_BOF_sa_netlocalgroup2
{
    meta:
        description = "Compiled Rust BOF: netlocalgroup2"
        author = "memN0ps"

    strings:
        $crate = "netlocalgroup2" ascii
        $capability = "go" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
