rule Armory_BOF_sa_arp
{
    meta:
        description = "Compiled Rust BOF: arp"
        author = "memN0ps"

    strings:
        $crate = "arp" ascii
        $capability = "No ARP entries found." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
