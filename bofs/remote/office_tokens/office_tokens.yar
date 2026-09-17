rule Armory_BOF_remote_office_tokens
{
    meta:
        description = "Compiled Rust BOF: office_tokens"
        author = "memN0ps"

    strings:
        $crate = "office_tokens" ascii
        $capability = "office_tokens: Scanning process " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
