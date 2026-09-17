rule Armory_BOF_sa_findLoadedModule
{
    meta:
        description = "Compiled Rust BOF: findLoadedModule"
        author = "memN0ps"

    strings:
        $crate = "findLoadedModule" ascii
        $capability = "Enumerated all processes but didn't find module '" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
