import sys, os, math, random, time, zlib, secrets, threading, time, asyncio


async def say_after(delay, what):
    await asyncio.sleep(delay)
    return what


async def main():
    taskvec=[]
    for i in range(10):
        taskvec.append(asyncio.create_task(say_after(i,str(i))))

    print(f"started at {time.strftime('%X')}")
    for task in taskvec:
        print(await task)
    print(f"finished at {time.strftime('%X')}")


asyncio.run(main())