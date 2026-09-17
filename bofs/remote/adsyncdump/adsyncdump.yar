rule Armory_BOF_remote_adsyncdump
{
    meta:
        description = "Compiled Rust BOF: adsyncdump"
        author = "memN0ps"

    strings:
        $crate = "adsyncdump" ascii
        $capability = "No supported SQL Server ODBC driver was found: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
