# ask_mfa

Displays a fake MFA prompt dialog to the user using `MessageBoxA`. Reports whether the user clicked OK or Cancel for each prompt.

## MITRE ATT&CK

- T1056.002 - Input Capture: GUI Input Capture

## Arguments

- `int`: Number of prompts to display (default: 1).

## Build

```text
cd bofs/remote/ask_mfa
cargo make
```

## Example

```text
beacon> ask_mfa <packed-arguments>
SUCCESS.
ask_mfa: Displaying <value> MFA prompt(s)
Prompt <value>: User clicked <value>
```

The command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.
