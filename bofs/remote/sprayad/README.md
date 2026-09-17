# sprayad

Validates one password against a bounded comma-separated account list with network logons. Successful tokens are closed immediately and no process is created. Incorrect use can lock accounts.

## MITRE ATT&CK

- T1110.003 - Brute Force: Password Spraying

## Arguments

- `str`: Domain name.
- `str`: Comma-separated usernames, maximum 32.
- `str`: Password.
- `int`: Delay between attempts in milliseconds, 0 to 60000.
- `str`: Literal `I_UNDERSTAND_LOCKOUT_RISK` confirmation.

## Build

```text
cd bofs/remote/sprayad
cargo make
```

## Example

```text
beacon> sprayad <packed-arguments>
[+] Password validation complete: attempted=<value> valid=<value> locked=<value>
[*] Account limit reached; remaining values were not attempted.
[+] Valid credential: <value>\<value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
