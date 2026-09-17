# askcreds

Displays the native Windows credential dialog and returns the username, domain, and password entered by the interactive user. The dialog does not persist the submitted credential.

## MITRE ATT&CK

- T1056.002 - Input Capture: GUI Input Capture

## Arguments

- `str`: Dialog caption.
- `str`: Dialog message.

## Build

```text
cd bofs/remote/askcreds
cargo make
```

## Example

```text
beacon> askcreds <packed-arguments>
[*] Credential dialog cancelled.
[+] Username: <value>
[+] Domain:   <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
