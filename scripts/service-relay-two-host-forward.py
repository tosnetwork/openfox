#!/usr/bin/env python3
"""A plain TCP forwarder for scripts/service-relay-two-host-e2e.sh.

    service-relay-two-host-forward.py <listen host> <target host> <port>...

Listens on <listen host>:<port> for each port and copies bytes both ways to
<target host>:<port>. It interprets nothing. The run uses it twice for the
chain's JSON-RPC: on the host end of the bridge, towards the validators on
127.0.0.1, and inside each node namespace on 127.0.0.1, towards the host end
of the bridge, because a node accepts plain-HTTP RPC endpoints only on
loopback. Prints "ready" once every port listens. Standard library only.
"""

import asyncio
import sys


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


async def handle(reader, writer, target: tuple) -> None:
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(*target)
    except OSError:
        writer.close()
        return
    await asyncio.gather(pipe(reader, upstream_writer), pipe(upstream_reader, writer), return_exceptions=True)


async def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    listen, target = sys.argv[1], sys.argv[2]
    servers = []
    for port in (int(value) for value in sys.argv[3:]):
        servers.append(await asyncio.start_server(
            lambda r, w, p=port: handle(r, w, (target, p)), listen, port, reuse_address=True))
    print("ready", flush=True)
    await asyncio.gather(*(server.serve_forever() for server in servers))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
