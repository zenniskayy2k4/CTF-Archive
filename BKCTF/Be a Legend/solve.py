import asyncio
import re
import ssl
import time
import websockets

HIT_RE = re.compile(r"You hit the dragon for (\d+) damage\. Dragon HP:\s*([\d,]+)")
DRAGON_HIT_RE = re.compile(r"The dragon hits you for ([\d,]+) damage\. Your HP:\s*(-?\d+)")
FLAG_RE = re.compile(r"FLAG:\s*(.+)")

URI = "wss://be-a-legend-558213881bb55bcb.instancer.batmans.kitchen/ws"

# Mục tiêu: LOAD trước cú đánh của rồng (server sleep ~0.3s).
# Nếu mạng lag, giảm dần xuống 0.22; nếu bị “You're already in combat!” spam do lệnh dồn, tăng chút.
LOAD_DELAY_DEFAULT = 0.25
LOAD_DELAY_MIN = 0.18
LOAD_DELAY_MAX = 0.29

PRINT_EVERY_N_HITS = 50


async def run_once(load_delay: float) -> float:
    """
    Chạy một phiên kết nối. Trả về load_delay mới (có thể tự chỉnh).
    """
    ssl_context = ssl._create_unverified_context()

    async with websockets.connect(
        URI,
        ssl=ssl_context,
        ping_interval=15,
        ping_timeout=15,
        close_timeout=2,
        max_queue=64,
    ) as ws:
        # đọc banner (không spam print)
        try:
            banner = await asyncio.wait_for(ws.recv(), timeout=2.5)
            print(banner)
        except asyncio.TimeoutError:
            pass

        await ws.send("FIGHT")

        hit_count = 0
        last_event = None  # "player_hit" | "dragon_hit" | None
        last_progress_ts = time.monotonic()

        scheduled_load_task: asyncio.Task | None = None

        async def schedule_load(delay_s: float):
            nonlocal scheduled_load_task
            if scheduled_load_task and not scheduled_load_task.done():
                scheduled_load_task.cancel()

            async def _do():
                await asyncio.sleep(delay_s)
                try:
                    await ws.send("LOAD")
                except Exception:
                    pass

            scheduled_load_task = asyncio.create_task(_do())

        async def reset_and_fight(reason: str):
            nonlocal last_event, scheduled_load_task
            print(f"[!] RESET: {reason}")
            last_event = None
            if scheduled_load_task and not scheduled_load_task.done():
                scheduled_load_task.cancel()
            await ws.send("RESET")
            await ws.send("FIGHT")

        while True:
            # watchdog: nếu im quá lâu thì thử FIGHT lại (tránh đứng)
            if time.monotonic() - last_progress_ts > 6.0:
                await ws.send("FIGHT")
                last_progress_ts = time.monotonic()

            msg = await ws.recv()

            mflag = FLAG_RE.search(msg)
            if mflag:
                print(msg)
                return load_delay

            if "You're already in combat!" in msg:
                continue

            if "You are dead! Use RESET" in msg:
                await reset_and_fight("dead loop (poisoned state)")
                continue

            if msg.strip() == "PLAYER_DIED" or "You have died. Game Over." in msg:
                # cố LOAD; nếu state bị poison sẽ rơi vào nhánh RESET ở trên
                await ws.send("LOAD")
                continue

            mhit = HIT_RE.search(msg)
            if mhit:
                last_progress_ts = time.monotonic()
                last_event = "player_hit"
                hit_count += 1
                dragon_hp = int(mhit.group(2).replace(",", ""))

                if hit_count % PRINT_EVERY_N_HITS == 0 or dragon_hp <= 50:
                    print(f"[+] hit#{hit_count} dragon_hp={dragon_hp} (load_delay={load_delay:.3f}s)")

                # SAVE ngay
                await ws.send("SAVE")
                # và lên lịch LOAD trước cú đánh của rồng
                await schedule_load(load_delay)
                continue

            mdrag = DRAGON_HIT_RE.search(msg)
            if mdrag:
                # LOAD bị trễ (hoặc server xử lý chậm) -> LOAD ngay và giảm delay chút cho các vòng sau
                last_progress_ts = time.monotonic()
                last_event = "dragon_hit"
                await ws.send("LOAD")
                load_delay = max(LOAD_DELAY_MIN, load_delay - 0.01)
                continue

            if "Game saved." in msg:
                # nếu save tới sau dragon_hit => khả năng poison
                if last_event != "player_hit":
                    await reset_and_fight("late SAVE detected")
                continue

            if "Game loaded." in msg:
                last_progress_ts = time.monotonic()
                continue


async def main():
    load_delay = LOAD_DELAY_DEFAULT

    while True:
        try:
            load_delay = await run_once(load_delay)
        except (websockets.exceptions.ConnectionClosedError, websockets.exceptions.ConnectionClosedOK) as e:
            print(f"[!] Disconnected: {e}. Reconnecting...")
            await asyncio.sleep(0.5)
        except asyncio.IncompleteReadError as e:
            print(f"[!] IncompleteReadError: {e}. Reconnecting...")
            await asyncio.sleep(0.5)
        except ssl.SSLError as e:
            print(f"[!] SSL error: {e}. Reconnecting...")
            await asyncio.sleep(0.8)


if __name__ == "__main__":
    asyncio.run(main())