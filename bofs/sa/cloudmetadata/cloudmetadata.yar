rule Armory_BOF_sa_cloudmetadata
{
    meta:
        description = "Compiled Rust BOF: cloudmetadata"
        author = "memN0ps"

    strings:
        $crate = "cloudmetadata" ascii
        $capability = "Fixed link-local endpoint | timeout: 2000 ms | response cap: 16384 bytes" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
