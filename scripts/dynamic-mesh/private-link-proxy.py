#!/usr/bin/env python3
"""Test-only TCP link between isolated cloud/local Docker networks; no TLS termination."""
import asyncio

async def main():
    capacity=asyncio.Semaphore(128)
    async def proxy(reader,writer,target,port):
        async with capacity:
            upstream=None
            try:
                source,upstream=await asyncio.wait_for(asyncio.open_connection(target,port),5)
                async def copy(source,destination):
                    while data:=await source.read(65536):
                        destination.write(data);await destination.drain()
                tasks=[asyncio.create_task(copy(reader,upstream)),asyncio.create_task(copy(source,writer))]
                await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
                for task in tasks:task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)
            except (OSError,asyncio.TimeoutError):pass
            finally:
                writer.close()
                if upstream:upstream.close()
    servers=[]
    for target,port in [('postgres',5432),('control',9091)]:
        async def handle(reader,writer,target=target,port=port):await proxy(reader,writer,target,port)
        servers.append(await asyncio.start_server(handle,'0.0.0.0',port))
    await asyncio.gather(*(server.serve_forever() for server in servers))
asyncio.run(main())
