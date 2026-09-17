rule Armory_BOF_sa_applocker
{
    meta:
        description = "Compiled Rust BOF: applocker"
        author = "memN0ps"

    strings:
        $crate = "applocker" ascii
        $capability = "Application Identity service: not available" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
