rule Armory_BOF_sa_wscstatus
{
    meta:
        description = "Compiled Rust BOF: wscstatus"
        author = "memN0ps"

    strings:
        $crate = "wscstatus" ascii
        $capability = "WscGetSecurityProviderHealth is unavailable" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
