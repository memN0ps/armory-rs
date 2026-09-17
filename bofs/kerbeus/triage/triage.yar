rule Armory_BOF_kerbeus_triage
{
    meta:
        description = "Compiled Rust BOF: triage"
        author = "memN0ps"

    strings:
        $crate = "triage" ascii
        $capability = "Action: List Kerberos Tickets (Current User)" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
