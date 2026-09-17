rule Armory_BOF_remote_make_token_cert
{
    meta:
        description = "Compiled Rust BOF: make_token_cert"
        author = "memN0ps"

    strings:
        $crate = "make_token_cert" ascii
        $capability = "No certificates found in the PFX." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
