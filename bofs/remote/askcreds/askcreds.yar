rule Armory_BOF_remote_askcreds
{
    meta:
        description = "Compiled Rust BOF: askcreds"
        author = "memN0ps"

    strings:
        $crate = "askcreds" ascii
        $capability = "[*] Credential dialog cancelled." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
