rule Armory_BOF_sa_ipconfig
{
    meta:
        description = "Compiled Rust BOF: ipconfig"
        author = "memN0ps"

    strings:
        $crate = "ipconfig" ascii
        $capability = "Windows IP Configuration" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
