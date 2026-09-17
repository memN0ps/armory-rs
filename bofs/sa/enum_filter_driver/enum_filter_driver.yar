rule Armory_BOF_sa_enum_filter_driver
{
    meta:
        description = "Compiled Rust BOF: enum_filter_driver"
        author = "memN0ps"

    strings:
        $crate = "enum_filter_driver" ascii
        $capability = "Total filter drivers found: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
