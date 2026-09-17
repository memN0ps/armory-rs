rule Armory_BOF_sa_netlocalgroup
{
    meta:
        description = "Compiled Rust BOF: netlocalgroup"
        author = "memN0ps"

    strings:
        $crate = "netlocalgroup" ascii
        $capability = ". Use 0 for groups, 1 for members." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
