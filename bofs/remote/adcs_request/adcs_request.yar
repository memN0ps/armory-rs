rule Armory_BOF_remote_adcs_request
{
    meta:
        description = "Compiled Rust BOF: adcs_request"
        author = "memN0ps"

    strings:
        $crate = "adcs_request" ascii
        $capability = "=== ADCS Certificate Template Enumeration (T1649) ===" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
