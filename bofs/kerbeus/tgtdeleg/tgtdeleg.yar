rule Armory_BOF_kerbeus_tgtdeleg
{
    meta:
        description = "Compiled Rust BOF: tgtdeleg"
        author = "memN0ps"

    strings:
        $crate = "tgtdeleg" ascii
        $capability = "[!] Full TGT extraction requires decrypting the authenticator with the session key from the ticket cache" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
