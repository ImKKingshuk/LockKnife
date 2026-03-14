# Legacy Interactive Mode Walkthrough

LockKnife includes a classic "menu" interactive mode designed for quick, manual workflows in a terminal.

This mode is separate from:

- the TUI (default `lockknife` with no subcommand)
- the headless Click CLI (command groups like `device`, `extract`, `forensics`, etc.)

## Start interactive mode

```bash
lockknife interactive
```

To preselect a device serial (optional):

```bash
lockknife interactive -s <serial>
```

## How it works

- You will see a numbered menu.
- Choose an action, then answer prompts (for example, device serial and a row limit).
- Results are printed to stdout (often as JSON).

## Example flow

x. Run `lockknife interactive`.
x. Choose **Device: list** to see available device serials.
x. Choose **Device: info** to print device properties.
x. Choose one of the extraction actions (SMS, contacts, call logs, browser, messaging, etc.).

## Notes

- Interactive mode is intended for simple/manual runs.
- For case-managed artifact registration, reporting, and exports, prefer either:
  - the TUI workflow, or
  - the headless CLI walkthrough with `--case-dir` and `case init`.
