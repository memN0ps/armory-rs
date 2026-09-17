rule Armory_BOF_kerbeus_dump
{
    meta:
        description = "Compiled Rust BOF: dump"
        author = "memN0ps"

    strings:
        $crate = "dump" ascii
        $capability = "Action: Dump Kerberos Tickets (Current User)" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
