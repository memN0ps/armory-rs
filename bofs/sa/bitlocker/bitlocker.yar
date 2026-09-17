rule Armory_BOF_sa_bitlocker
{
    meta:
        description = "Compiled Rust BOF: bitlocker"
        author = "memN0ps"

    strings:
        $crate = "bitlocker" ascii
        $capability = "No encryptable volumes were returned." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
