rule Armory_BOF_remote_suspendresume
{
    meta:
        description = "Compiled Rust BOF: suspendresume"
        author = "memN0ps"

    strings:
        $crate = "suspendresume" ascii
        $capability = "SeDebugPrivilege not available (non-fatal)." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
