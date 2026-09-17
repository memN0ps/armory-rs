rule Armory_BOF_remote_ask_mfa
{
    meta:
        description = "Compiled Rust BOF: ask_mfa"
        author = "memN0ps"

    strings:
        $crate = "ask_mfa" ascii
        $capability = "ask_mfa: Displaying " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
