rule Armory_BOF_sa_netgroup
{
    meta:
        description = "Compiled Rust BOF: netgroup"
        author = "memN0ps"

    strings:
        $crate = "netgroup" ascii
        $capability = ". Use 0 for groups, 1 for members." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
