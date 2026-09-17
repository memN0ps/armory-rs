rule Armory_BOF_sa_list_firewall_rules
{
    meta:
        description = "Compiled Rust BOF: list_firewall_rules"
        author = "memN0ps"

    strings:
        $crate = "list_firewall_rules" ascii
        $capability = "Windows Firewall Rules (from registry):" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
