rule Armory_BOF_remote_ghost_task
{
    meta:
        description = "Compiled Rust BOF: ghost_task"
        author = "memN0ps"

    strings:
        $crate = "ghost_task" ascii
        $capability = "Path:    HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
