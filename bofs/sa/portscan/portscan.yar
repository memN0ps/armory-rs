rule Armory_BOF_sa_portscan
{
    meta:
        description = "Compiled Rust BOF: portscan"
        author = "memN0ps"

    strings:
        $crate = "portscan" ascii
        $capability = "Ports must be top20, a comma list, or bounded ranges (maximum 256 ports)." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
