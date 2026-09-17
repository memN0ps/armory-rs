# tgtdeleg

Extracts a usable TGT via the Kerberos GSS-API delegation trick. Uses AcquireCredentialsHandle and InitializeSecurityContext with ISC_REQ_DELEGATE to create a delegated AP-REQ containing a KRB-CRED with the user TGT in the authenticator checksum.

## MITRE ATT&CK

- T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

## Arguments

- `/target:SPN` - Target SPN for delegation (default: CIFS/DC)

## Build

```text
cd bofs/kerbeus/tgtdeleg
cargo make
```

## Example

```text
beacon> tgtdeleg <packed-arguments>
[!] Full TGT extraction requires decrypting the authenticator with the session key from the ticket cache
[!] This requires LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage) to get the session key
[!] Implementation pending - the SSPI delegation succeeded, TGT is in the token
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
