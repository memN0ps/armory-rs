rule Armory_BOF_sa_wmi_query
{
    meta:
        description = "Compiled Rust BOF: wmi_query"
        author = "memN0ps"

    strings:
        $crate = "wmi_query" ascii
        $capability = "<property output limit reached>" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
