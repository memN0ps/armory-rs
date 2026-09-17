rule Armory_BOF_kerbeus_klist
{
    meta:
        description = "Compiled Rust BOF: klist"
        author = "memN0ps"

    strings:
        $crate = "klist" ascii
        $capability = "Action: List Kerberos Tickets (Current User)" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
