rule Armory_BOF_injection_ntqueueapcthread
{
    meta:
        description = "Compiled Rust BOF: ntqueueapcthread"
        author = "memN0ps"

    strings:
        $crate = "ntqueueapcthread" ascii
        $capability = "NtQueueApcThread injection into PID: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
