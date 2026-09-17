rule Armory_BOF_sa_routeprint
{
    meta:
        description = "Compiled Rust BOF: routeprint"
        author = "memN0ps"

    strings:
        $crate = "routeprint" ascii
        $capability = "go" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
