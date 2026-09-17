rule Armory_BOF_remote_screenshot
{
    meta:
        description = "Compiled Rust BOF: screenshot"
        author = "memN0ps"

    strings:
        $crate = "screenshot" ascii
        $capability = "[+] Screenshot captured: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
