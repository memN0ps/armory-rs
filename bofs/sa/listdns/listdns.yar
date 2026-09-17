rule Armory_BOF_sa_listdns
{
    meta:
        description = "Compiled Rust BOF: listdns"
        author = "memN0ps"

    strings:
        $crate = "listdns" ascii
        $capability = "No DNS cache entries found" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
