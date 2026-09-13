rule Rust_CobaltStrike_Kernel_BOF
{
    meta:
        description = "Detects the armory-rs driver-agnostic kernel BOF family"
        author = "memN0ps"
        version = "0.1.0"
        scope = "compiled AMD64 COFF object"

    strings:
        $entry = "go" ascii
        $beacon_output = "BeaconOutput" ascii
        $adapter = "driver-agnostic adapter" ascii
        $kernel_read = "Kernel read" ascii
        $physical_write = "Physical write" ascii
        $no_change = "No kernel state was changed" ascii

    condition:
        uint16(0) == 0x8664 and
        uint16(2) >= 3 and uint16(2) <= 32 and
        $entry and $beacon_output and
        3 of ($adapter, $kernel_read, $physical_write, $no_change)
}
