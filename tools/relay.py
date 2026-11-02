#!/usr/bin/env python3
"""Relais TCP de tournage : rend un panel joignable depuis Windows à l'adresse localhost.

Le VPN tourne dans WSL, donc Chrome sous Windows ne joint pas les panels. Ce relais écoute
sur 127.0.0.1 dans WSL (WSL partage ces ports avec Windows) et transmet tout, octet pour octet,
vers le panel à travers le tunnel. Le chiffrement TLS reste de bout en bout entre Chrome et le
panel : le relais ne voit que des données chiffrées.

Usage : tools/relay.py PORT_LOCAL:HÔTE:PORT [PORT_LOCAL:HÔTE:PORT ...]
Ctrl+C pour arrêter.
"""

import asyncio
import sys


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


def handler(host: str, port: int):
    async def handle(client_reader, client_writer):
        try:
            remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
        except (OSError, asyncio.TimeoutError):
            print("Panel injoignable : le tunnel WireGuard est-il monté ?", file=sys.stderr)
            client_writer.close()
            return
        await asyncio.gather(pipe(client_reader, remote_writer), pipe(remote_reader, client_writer))
    return handle


async def main(specs: list[str]):
    servers = []
    for spec in specs:
        local, host, port = spec.split(":")
        server = await asyncio.start_server(handler(host, int(port)), "127.0.0.1", int(local))
        servers.append(server)
        print(f"Relais prêt : https://localhost:{local}")
    print("Ctrl+C pour arrêter.")
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    try:
        asyncio.run(main(sys.argv[1:]))
    except KeyboardInterrupt:
        pass
