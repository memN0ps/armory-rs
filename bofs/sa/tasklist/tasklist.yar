rule Armory_BOF_sa_tasklist
{
    meta:
        description = "Compiled Rust BOF: tasklist"
        author = "memN0ps"

    strings:
        $crate = "tasklist" ascii
        $capability = "Process inventory" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
