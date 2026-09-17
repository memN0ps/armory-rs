rule Armory_BOF_sa_resources
{
    meta:
        description = "Compiled Rust BOF: resources"
        author = "memN0ps"

    strings:
        $crate = "resources" ascii
        $capability = "Error fetching disk space" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
