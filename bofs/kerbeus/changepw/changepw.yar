rule Armory_BOF_kerbeus_changepw
{
    meta:
        description = "Compiled Rust BOF: changepw"
        author = "memN0ps"

    strings:
        $crate = "changepw" ascii
        $capability = "[*] Sending authenticated password request to " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
