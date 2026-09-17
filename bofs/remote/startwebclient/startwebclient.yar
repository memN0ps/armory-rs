rule Armory_BOF_remote_startwebclient
{
    meta:
        description = "Compiled Rust BOF: startwebclient"
        author = "memN0ps"

    strings:
        $crate = "startwebclient" ascii
        $capability = "[+] WebClient started and the running state was verified." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
