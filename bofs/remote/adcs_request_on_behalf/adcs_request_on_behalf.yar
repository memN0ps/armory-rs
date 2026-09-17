rule Armory_BOF_remote_adcs_request_on_behalf
{
    meta:
        description = "Compiled Rust BOF: adcs_request_on_behalf"
        author = "memN0ps"

    strings:
        $crate = "adcs_request_on_behalf" ascii
        $capability = "=== ADCS Certificate Request On Behalf (T1649) ===" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
