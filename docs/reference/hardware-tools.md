# Hardware Tools

OpenFox provides optional tools for serial, I2C, and SPI hardware access. They
operate on host devices and are disabled by default. Enable only the tools and
device access required by the deployment.

## Support Matrix

| Capability | Linux | macOS | Windows | Actions |
| --- | --- | --- | --- | --- |
| Serial | Yes | Yes | Yes | `list`, `read`, `write` |
| I2C | Yes | No | No | `detect`, `scan`, `read`, `write` |
| SPI | Yes | No | No | `list`, `transfer`, `read` |
| USB device events | Yes | No | No | Device discovery and notification |

I2C and SPI access uses `/dev/i2c-*` and `/dev/spidev*`. USB device events are
discovery signals; they do not grant bus read or write access.

## Configuration

Enable a hardware tool explicitly in the OpenFox configuration:

```json
{
  "tools": {
    "serial": { "enabled": true },
    "i2c": { "enabled": false },
    "spi": { "enabled": false }
  }
}
```

The host process must also have operating-system permission to access the
selected device. Container deployments must expose each required device
explicitly.

## Serial Behavior

The `serial` tool opens and closes the port for every call. It does not preserve
a serial session between Agent turns.

- `list` enumerates available ports.
- `read` reads between 1 and 4,096 bytes.
- `write` accepts bytes or UTF-8 text up to 4,096 bytes and requires
  `confirm: true`.
- The default configuration is 115,200 baud, 8 data bits, no parity, one stop
  bit, and a 1,000 ms timeout.
- Timeouts may be set from 1 to 60,000 ms.
- Linux and macOS accept standard termios rates through 230,400 baud. Windows
  accepts configured rates from 50 through 4,000,000 baud.

Port names are restricted to recognized serial-device forms. Unix platforms
accept supported `/dev/tty*`, `/dev/cu.*`, and equivalent short names. Windows
accepts `COM1` and higher, including the canonical `\\.\COMn` form. Arbitrary
paths, traversal, drive paths, and network shares are rejected.

Windows uses bounded synchronous I/O. Cancellation may therefore take until the
configured OS timeout after a read or write system call has started.

## Operational Safety

- Keep hardware tools disabled when they are not required.
- Grant access to specific devices, not the whole host device namespace.
- Treat reads as potentially sensitive and writes as physical side effects.
- Obtain user confirmation before serial writes; the tool also enforces the
  `confirm` flag.
- Apply deployment policy and sandboxing outside the model. Model output is not
  device authorization.
- Use a dedicated hardware adapter or session service for long-lived,
  interactive device protocols instead of repeated Agent tool calls.
