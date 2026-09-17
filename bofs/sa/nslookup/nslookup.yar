rule Armory_BOF_sa_nslookup
{
    meta:
        description = "Compiled Rust BOF: nslookup"
        author = "memN0ps"

    strings:
        $crate = "nslookup" ascii
        $capability = "DNS query results for '" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
