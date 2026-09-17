rule Armory_BOF_remote_sprayad
{
    meta:
        description = "Compiled Rust BOF: sprayad"
        author = "memN0ps"

    strings:
        $crate = "sprayad" ascii
        $capability = "[*] Account limit reached; remaining values were not attempted." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
