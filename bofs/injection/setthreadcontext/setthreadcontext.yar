rule Armory_BOF_injection_setthreadcontext
{
    meta:
        description = "Compiled Rust BOF: setthreadcontext"
        author = "memN0ps"

    strings:
        $crate = "setthreadcontext" ascii
        $capability = "SetThreadContext injection into PID: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
