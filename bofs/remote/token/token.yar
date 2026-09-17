rule Armory_BOF_remote_token
{
    meta:
        description = "Compiled Rust BOF: token"
        author = "memN0ps"

    strings:
        $crate = "token" ascii
        $capability = "[+] Impersonating a duplicated token from PID " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
