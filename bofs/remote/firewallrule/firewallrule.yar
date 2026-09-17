rule Armory_BOF_remote_firewallrule
{
    meta:
        description = "Compiled Rust BOF: firewallrule"
        author = "memN0ps"

    strings:
        $crate = "firewallrule" ascii
        $capability = ". Run remove with the same exact name to roll it back." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
