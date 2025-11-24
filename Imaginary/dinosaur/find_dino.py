#!/usr/bin/env python3
import json, datetime

DISCORD_EPOCH_MS = 1420070400000  # Jan 1, 2015 UTC

def snowflake_to_datetime(sf: int) -> datetime.datetime:
    """Convert Discord snowflake to UTC datetime"""
    ts_ms = (sf >> 22) + DISCORD_EPOCH_MS
    return datetime.datetime.utcfromtimestamp(ts_ms / 1000.0).replace(tzinfo=datetime.timezone.utc)

# === CONFIG ===
snowflake_target = 732334696565964811   # số bạn thấy lặp lại trong file
ts_target = snowflake_to_datetime(snowflake_target)
print("Snowflake:", snowflake_target, "->", ts_target.isoformat())

# === Load JSON export ===
# Thay "export.json" = file bạn export từ Discord (messages/emojis/server dump)
with open("export.json", encoding="utf-8") as f:
    data = json.load(f)

# === Lọc các object có timestamp gần với ts_target ===
def parse_dt(s):
    try:
        return datetime.datetime.fromisoformat(s.replace("Z","+00:00"))
    except:
        return None

matches = []

def scan(obj, path=""):
    if isinstance(obj, dict):
        for k,v in obj.items():
            if isinstance(v,str):
                # Nếu có field timestamp
                if "time" in k.lower():
                    dt = parse_dt(v)
                    if dt:
                        delta = abs((dt - ts_target).total_seconds())
                        if delta < 60*60:  # trong vòng 1 giờ
                            matches.append((path+"."+k, v, delta))
            else:
                scan(v, path+"."+k)
    elif isinstance(obj,list):
        for i,v in enumerate(obj):
            scan(v, path+f"[{i}]")

scan(data)

matches.sort(key=lambda x: x[2])
for m in matches[:10]:
    print("Near match:", m)
