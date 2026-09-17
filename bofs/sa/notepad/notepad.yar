rule Armory_BOF_sa_notepad
{
    meta:
        description = "Compiled Rust BOF: notepad"
        author = "memN0ps"

    strings:
        $crate = "notepad" ascii
        $capability = "Edit control not found in Notepad" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
