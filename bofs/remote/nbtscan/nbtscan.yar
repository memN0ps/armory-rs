rule Armory_BOF_remote_nbtscan
{
    meta:
        description = "Compiled Rust BOF: nbtscan"
        author = "memN0ps"

    strings:
        $crate = "nbtscan" ascii
        $capability = "NetBIOS name scan | target=" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
