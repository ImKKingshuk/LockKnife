# Classic Interactive Mode

Classic interactive mode provides numbered terminal menus for simple manual tasks. It is separate from the full-screen TUI and the scriptable CLI.

## Start

```bash
lockknife --cli interactive
```

To preselect an authorized device, replace `EXAMPLE_DEVICE_SERIAL` with a serial returned by `device list`:

```bash
lockknife --cli interactive --serial EXAMPLE_DEVICE_SERIAL
```

## Example Workflow

1. Choose **Device: list** to inspect available device serials.
2. Choose **Device: info** to view properties for the intended device.
3. Select an extraction or local analysis action and provide the requested input.
4. Review the result, then choose `q` to leave the menu.

Results are printed to the terminal or written to a requested output file. Terminal output may contain sensitive evidence; avoid recording or sharing it without review.

## Case-Based Investigations

For case-managed registration, provenance, integrity checks, and reporting, use the [TUI walkthrough](tui-walkthrough.md) or [CLI walkthrough](headless-cli-walkthrough.md). Classic mode does not provide the same case workflow as those interfaces.
