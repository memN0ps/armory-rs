rule Armory_BOF_sa_netloggedon2
{
    meta:
        description = "Compiled Rust BOF: netloggedon2"
        author = "memN0ps"

    strings:
        $crate = "netloggedon2" ascii
        $capability = "\",\"logon_server\":\"" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
