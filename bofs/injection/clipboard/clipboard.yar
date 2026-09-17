rule Armory_BOF_injection_clipboard
{
    meta:
        description = "Compiled Rust BOF: clipboard"
        author = "memN0ps"

    strings:
        $crate = "clipboard" ascii
        $capability = "SUCCESS - clipboard injection variant, remote thread created." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
