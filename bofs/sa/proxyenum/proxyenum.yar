rule Armory_BOF_sa_proxyenum
{
    meta:
        description = "Compiled Rust BOF: proxyenum"
        author = "memN0ps"

    strings:
        $crate = "proxyenum" ascii
        $capability = "WinHTTP proxy:          " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
