rule Armory_BOF_sa_adv_audit_policies
{
    meta:
        description = "Compiled Rust BOF: adv_audit_policies"
        author = "memN0ps"

    strings:
        $crate = "adv_audit_policies" ascii
        $capability = "=== Advanced Audit Policy Settings ===" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
