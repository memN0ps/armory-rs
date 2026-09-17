rule Armory_BOF_remote_get_azure_token
{
    meta:
        description = "Compiled Rust BOF: get_azure_token"
        author = "memN0ps"

    strings:
        $crate = "get_azure_token" ascii
        $capability = "get_azure_token: Reading Azure/Office OAuth token cache" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
