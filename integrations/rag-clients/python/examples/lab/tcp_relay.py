"""LAB ONLY: plain TCP relay standing in for the customer's load balancer, so the
RAG container itself can stay on an internal network with no route to the
host, the model backend or the internet."""
import asyncio
import sys

LISTEN_PORT, TARGET_HOST, TARGET_PORT = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])


async def pipe(r, w):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    finally:
        w.close()


async def handle(cr, cw):
    try:
        tr, tw = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
    except OSError:
        cw.close()
        return
    await asyncio.gather(pipe(cr, tw), pipe(tr, cw), return_exceptions=True)


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", LISTEN_PORT)
    async with server:
        await server.serve_forever()

asyncio.run(main())
