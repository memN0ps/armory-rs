rule Armory_BOF_kerbeus_hash
{
    meta:
        description = "Compiled Rust BOF: hash"
        author = "memN0ps"

    strings:
        $crate = "hash" ascii
        $capability = "[*] Action: Calculate Password Hash(es)" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
