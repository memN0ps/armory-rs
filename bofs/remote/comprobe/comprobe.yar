rule Armory_BOF_remote_comprobe
{
    meta:
        description = "Compiled Rust BOF: comprobe"
        author = "memN0ps"

    strings:
        $crate = "comprobe" ascii
        $capability = "COM activation probe | CLSID=" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
