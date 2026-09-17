rule Armory_BOF_sa_appcount
{
    meta:
        description = "Compiled Rust BOF: appcount"
        author = "memN0ps"

    strings:
        $crate = "appcount" ascii
        $capability = "Installed application count" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
