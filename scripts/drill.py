#!/usr/bin/env python3
"""Black-box drill client for the isolated DHCPv4 lab.

Speaks real DHCPv4 over UDP and reads the web API over HTTP. Standard library
only, so it can run on the host without installing project dependencies.

Examples (against `docker compose up -d`):
    python3 scripts/drill.py contend
    python3 scripts/drill.py race --clients 12
    python3 scripts/drill.py expire
    python3 scripts/drill.py restart-before --state /tmp/dhcp-restart.json
    docker compose restart dhcp
    python3 scripts/drill.py restart-after --state /tmp/dhcp-restart.json

Options via environment or flags: --host, --port, --api.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

MAGIC = b"\x63\x82\x53\x63"
DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE = 1, 2, 3, 5, 6, 7


# --------------------------------------------------------------------------
# Minimal DHCP codec (mirrors app/dhcp/packet.py, kept independent on purpose)
# --------------------------------------------------------------------------


def options_block(options: dict[int, bytes]) -> bytes:
    out = b""
    for code, value in sorted(options.items()):
        out += bytes((code, len(value))) + value
    return out + b"\xff"


def build(mac: str, xid: int, msg_type: int, opts: dict[int, bytes],
          ciaddr: str = "0.0.0.0") -> bytes:
    chaddr = bytes.fromhex(mac.replace(":", "")).ljust(16, b"\x00")
    header = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1, 1, 6, 0, xid, 0, 0x8000,
        ipaddress.IPv4Address(ciaddr).packed,
        b"\x00" * 4, b"\x00" * 4, b"\x00" * 4,
        chaddr, b"\x00" * 64, b"\x00" * 128,
    )
    return header + MAGIC + options_block({53: bytes((msg_type,)), **opts})


def parse(data: bytes) -> dict:
    if len(data) < 240 or data[236:240] != MAGIC:
        raise ValueError(f"not a DHCP packet ({len(data)} bytes)")
    fields = struct.unpack("!BBBBIHH4s4s4s4s16s64s128s", data[:236])
    result = {
        "op": fields[0],
        "xid": fields[4],
        "flags": fields[6],
        "ciaddr": str(ipaddress.IPv4Address(fields[7])),
        "yiaddr": str(ipaddress.IPv4Address(fields[8])),
        "giaddr": str(ipaddress.IPv4Address(fields[10])),
        "chaddr": fields[11][: fields[2]].hex(":"),
        "options": {},
    }
    index, options = 240, {}
    while index < len(data):
        code = data[index]
        index += 1
        if code == 0:
            continue
        if code == 255:
            break
        length = data[index]
        index += 1
        value = data[index:index + length]
        index += length
        options.setdefault(code, []).append(value)
    for code, values in options.items():
        raw = values[0]
        if code in (1, 3, 6, 28, 50, 54) and len(raw) in (4, 8, 12, 16):
            result["options"][code] = [
                str(ipaddress.IPv4Address(raw[i:i + 4]))
                for i in range(0, len(raw), 4)
            ]
        elif code in (51, 58, 59) and len(raw) == 4:
            result["options"][code] = struct.unpack("!I", raw)[0]
        elif code in (12, 56):
            result["options"][code] = raw.decode("utf-8", "replace")
        elif code == 53 and len(raw) == 1:
            result["options"][code] = raw[0]
        else:
            result["options"][code] = raw.hex()
    result["type"] = result["options"].get(53)
    return result


TYPE_NAME = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 6: "NAK", 7: "RELEASE"}


# --------------------------------------------------------------------------
# Transport helpers
# --------------------------------------------------------------------------


class Lab:
    def __init__(self, host: str, port: int, api: str, timeout: float) -> None:
        self.host = host
        self.port = port
        self.api = api.rstrip("/")
        self.timeout = timeout

    def send(self, payload: bytes) -> dict | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(payload, (self.host, self.port))
            data, _ = sock.recvfrom(4096)
            return parse(data)
        except socket.timeout:
            return None
        finally:
            sock.close()

    def discover(self, mac: str, xid: int | None = None) -> dict | None:
        xid = xid or uuid.uuid4().int & 0xFFFFFFFF
        return self.send(build(mac, xid, DISCOVER, {61: b"\x01" + bytes.fromhex(mac.replace(":", ""))}))

    def request(self, mac: str, ip: str | None = None, *, ciaddr: str = "0.0.0.0",
                server_id: str | None = None, xid: int | None = None) -> dict | None:
        opts: dict[int, bytes] = {
            61: b"\x01" + bytes.fromhex(mac.replace(":", "")),
        }
        if ip:
            opts[50] = ipaddress.IPv4Address(ip).packed
        if server_id:
            opts[54] = ipaddress.IPv4Address(server_id).packed
        return self.send(build(mac, xid or uuid.uuid4().int & 0xFFFFFFFF, REQUEST, opts, ciaddr=ciaddr))

    def release(self, mac: str, ip: str, server_id: str | None = None) -> None:
        opts = {61: b"\x01" + bytes.fromhex(mac.replace(":", ""))}
        if server_id:
            opts[54] = ipaddress.IPv4Address(server_id).packed
        self.send(build(mac, uuid.uuid4().int & 0xFFFFFFFF, RELEASE, opts, ciaddr=ip))

    def get(self, path: str) -> dict:
        with urllib.request.urlopen(self.api + path, timeout=5) as response:
            return json.loads(response.read())

    def state(self) -> dict:
        return self.get("/api/state")

    def server_id(self) -> str:
        return self.state()["config"]["server_id"]

    def wait_health(self, seconds: float = 30.0) -> None:
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                self.get("/api/health")
                return
            except (urllib.error.URLError, OSError):
                time.sleep(0.3)
        raise SystemExit(f"web API at {self.api} did not become healthy")


def lease_map(lab: Lab) -> dict[str, dict]:
    return {lease["ip"]: lease for lease in lab.state()["leases"]}


def ok(message: str) -> None:
    print(f"  \033[32mPASS\033[0m {message}")


def fail(message: str) -> None:
    print(f"  \033[31mFAIL\033[0m {message}")
    raise SystemExit(1)


def check(condition: bool, message: str) -> None:
    ok(message) if condition else fail(message)


def wait_until(predicate, timeout: float, interval: float = 0.5) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------


def scenario_contend(lab: Lab) -> None:
    print("== 争抢与归属 ==")
    lab.wait_health()
    before = lease_map(lab)
    mac_a, mac_b = "02:00:00:00:aa:01", "02:00:00:00:bb:02"
    if any(l["client_mac"] == mac_a for l in before.values()):
        fail("test MAC already owns a lease; restart with a clean volume first")

    offer_a = lab.discover(mac_a)
    check(offer_a is not None and offer_a["type"] == OFFER, "A 收到 OFFER")
    ip_a = offer_a["yiaddr"]

    offer_b = lab.discover(mac_b)
    check(offer_b is not None and offer_b["type"] == OFFER, "B 收到 OFFER")
    check(offer_b["yiaddr"] != ip_a, "B 的 OFFER 未占用 A 的预留地址")

    nak = lab.request(mac_b, ip_a, server_id=lab.server_id())
    check(nak is not None and nak["type"] == NAK, "B 冒领 A 的地址被 NAK")

    ack = lab.request(mac_a, ip_a, server_id=lab.server_id())
    check(ack is not None and ack["type"] == ACK and ack["yiaddr"] == ip_a,
          "A 确认自己的预留地址得到 ACK")
    check(lease_map(lab).get(ip_a, {}).get("status") == "bound", "A 的租约已落库为 bound")

    renew = lab.request(mac_a, None, ciaddr=ip_a, server_id=lab.server_id())
    check(renew is not None and renew["type"] == ACK, "A 可凭 ciaddr 续租")

    lab.release(mac_b, ip_a, lab.server_id())
    time.sleep(0.4)
    check(lease_map(lab).get(ip_a, {}).get("status") == "bound",
          "B 冒名 RELEASE 不影响 A 的租约")

    lab.release(mac_a, ip_a, lab.server_id())
    check(wait_until(lambda: ip_a not in lease_map(lab), 5), "A 释放后地址回到空闲池")

    # 释放后再次请求必须 NAK。
    stale = lab.request(mac_a, ip_a, server_id=lab.server_id())
    check(stale is not None and stale["type"] == NAK, "释放后旧地址再请求被 NAK")


def scenario_race(lab: Lab, clients: int) -> None:
    print(f"== 并发争抢（{clients} 个不同客户端同时 DISCOVER）==")
    lab.wait_health()
    free_before = lab.state()["stats"]["free"]
    results: list[str] = []
    silent: list[str] = []
    errors: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(clients)

    def worker(n: int) -> None:
        mac = f"02:00:00:01:{n // 256:02x}:{n % 256:02x}"
        try:
            barrier.wait(timeout=10)
            reply = lab.discover(mac)
            with lock:
                if reply is None:
                    silent.append(mac)
                elif reply["type"] != OFFER:
                    errors.append(f"{mac}: unexpected {TYPE_NAME.get(reply['type'])}")
                else:
                    results.append(reply["yiaddr"])
        except Exception as exc:  # noqa: BLE001 - drill reports detail
            with lock:
                errors.append(f"{mac}: {exc}")

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(clients)]
    started = time.time()
    [t.start() for t in threads]
    [t.join() for t in threads]
    used = lease_map(lab)
    configured = lab.state()["stats"]["pool_size"]
    capped = min(clients, free_before)
    print(
        f"  用时 {time.time() - started:.2f}s；池大小 {configured}；"
        f"开始时空闲 {free_before}；OFFER {len(results)}；无响应 {len(silent)}"
    )

    check(not errors, f"没有异常响应（{errors[:3]}）")
    check(len(set(results)) == len(results), "所有 OFFER 地址互不重复")
    check(len(results) == capped,
          f"恰好分配 {capped} 个（不超过空闲地址数，也不浪费）")
    if clients > free_before:
        check(len(silent) == clients - capped,
              "池耗尽时多余客户端得到静默而不是重复地址")

    by_ip: dict[str, str] = {}
    for ip, lease in used.items():
        key = lease["client_key"]
        if ip in by_ip and by_ip[ip] != key:
            fail(f"双重租用: {ip}")
        by_ip[ip] = key
    check(True, "状态库中没有地址被两个客户端同时持有")

    # Leave the pool clean so the next drill starts from a known state.
    server_id = lab.server_id()
    for n in range(clients):
        mac = f"02:00:00:01:{n // 256:02x}:{n % 256:02x}"
        lease = next((l for l in lease_map(lab).values()
                      if l["client_mac"] == mac), None)
        if lease:
            lab.release(mac, lease["ip"], server_id)
    check(wait_until(lambda: lab.state()["stats"]["used"] == 0, 8),
          "演练结束后地址池已清空")


def scenario_expire(lab: Lab) -> None:
    print("== 过期回收 ==")
    lab.wait_health()
    state = lab.state()
    ttl = float(state["config"]["offer_ttl"])
    mac_a, mac_b = "02:00:00:00:cc:03", "02:00:00:00:dd:04"
    offer = lab.discover(mac_a)
    check(offer is not None and offer["type"] == OFFER, "A 获得 OFFER")
    ip = offer["yiaddr"]
    print(f"  OFFER 有效期 {ttl:g}s；等待其过期…")
    time.sleep(ttl + 1.0)
    check(wait_until(lambda: ip not in lease_map(lab), 8),
          "预留到期后从状态库中被回收")
    offer_b = lab.discover(mac_b)
    check(offer_b is not None and offer_b["yiaddr"] == ip,
          "回收后的地址可分配给新客户端")
    stale = lab.request(mac_a, ip, server_id=lab.server_id())
    check(stale is not None and stale["type"] == NAK, "过期预留不能被原客户端再次确认")
    lab.release(mac_b, ip, lab.server_id())


def scenario_restart_before(lab: Lab, path: str) -> None:
    print("== 重启前：建立已确认租约 ==")
    lab.wait_health()
    mac = "02:00:00:00:ee:05"
    offer = lab.discover(mac)
    check(offer is not None and offer["type"] == OFFER, "收到 OFFER")
    ip = offer["yiaddr"]
    ack = lab.request(mac, ip, server_id=lab.server_id())
    check(ack is not None and ack["type"] == ACK, "收到 ACK")
    lease = lease_map(lab).get(ip, {})
    check(lease.get("status") == "bound", "租约已以 bound 状态落库")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"mac": mac, "ip": ip, "server_id": lab.server_id(),
                   "expires_at": lease.get("expires_at")}, handle)
    print(f"  已保存 {path}；现在重启服务：docker compose restart dhcp")


def scenario_restart_after(lab: Lab, path: str) -> None:
    print("== 重启后：租约仍有效且不可被抢 ==")
    with open(path, encoding="utf-8") as handle:
        saved = json.load(handle)
    lab.wait_health()
    mac, ip, server_id = saved["mac"], saved["ip"], saved["server_id"]
    lease = lease_map(lab).get(ip)
    check(lease is not None, "重启后仍能看到该租约")
    check(lease.get("status") == "bound", "状态仍为 bound")
    check(lease.get("expires_at") == saved["expires_at"], "到期时间未被重置")

    other = "02:00:00:00:ff:06"
    offer = lab.discover(other)
    check(offer is not None and offer["yiaddr"] != ip, "其他客户端不会拿到该地址")
    nak = lab.request(other, ip, server_id=server_id)
    check(nak is not None and nak["type"] == NAK, "其他客户端冒领被 NAK")
    renew = lab.request(mac, None, ciaddr=ip, server_id=server_id)
    check(renew is not None and renew["type"] == ACK, "原客户端重启后仍可续租")
    lab.release(mac, ip, server_id)
    if offer is not None:
        lab.release(other, offer["yiaddr"], server_id)


def _post(lab: Lab, path: str) -> dict:
    request = urllib.request.Request(
        lab.api + path, data=b"{}",
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return {"http_error": exc.code, "detail": exc.read().decode("utf-8", "replace")}


def scenario_commit_failure(lab: Lab) -> None:
    print("== 落库失败时不得 ACK ==")
    lab.wait_health()
    state = lab.state()
    if not state["config"].get("failure_injection"):
        print("  服务未开启 DHCP_ALLOW_FAILURE_INJECTION=1，跳过。")
        print("  该场景已在单元测试 test_commit_failure_sends_no_ack_and_persists_nothing 中验证。")
        return

    mac = "02:00:00:00:99:07"
    offer = lab.discover(mac)
    check(offer is not None and offer["type"] == OFFER, "先取得一个有效 OFFER")
    ip = offer["yiaddr"]
    server_id = lab.server_id()

    result = _post(lab, "/api/drill/inject-commit-failure?count=1")
    check(result.get("injected") == 1, "已注入下一次提交失败")

    silent = lab.request(mac, ip, server_id=server_id)
    check(silent is None, "提交失败时客户端收不到任何 ACK/NAK")
    status = lease_map(lab).get(ip, {}).get("status")
    check(status != "bound",
          f"租约未被提升为 bound（当前状态: {status or '已过期/不存在'}）")

    recovered = lab.request(mac, ip, server_id=server_id)
    check(recovered is not None and recovered["type"] == ACK,
          "注入解除后同一预留在重试中正常 ACK")
    lab.release(mac, ip, server_id)


def scenario_simulate(lab: Lab) -> None:
    print("== 网页模拟接口发真实报文 ==")
    lab.wait_health()
    body = json.dumps({"kind": "DISCOVER", "mac": "02:00:00:00:12:34"}).encode()
    request = urllib.request.Request(
        lab.api + "/api/simulate", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        data = json.loads(response.read())
    check(data.get("action") == "DHCPOFFER", "模拟接口返回 DHCPOFFER")
    check(data.get("reply", {}).get("yiaddr") is not None, "响应含 yiaddr")
    check(len(data.get("sent_hex", "")) > 0, "发送的是真实 DHCP 报文")
    ip = data["reply"]["yiaddr"]
    sid = data["reply"]["options"].get("54")
    if isinstance(sid, list):
        sid = sid[0]
    lab.release("02:00:00:00:12:34", ip, sid)
    print(f"  示例响应: {json.dumps(data['reply'], ensure_ascii=False)[:220]}…")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default=os.environ.get("DHCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DHCP_PORT", "6767")))
    parser.add_argument("--api", default=os.environ.get("DHCP_API", "http://127.0.0.1:8080"))
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--state", default="/tmp/dhcp-restart-state.json")
    sub = parser.add_subparsers(dest="scenario", required=True)
    sub.add_parser("contend")
    race = sub.add_parser("race")
    race.add_argument("--clients", type=int, default=12)
    sub.add_parser("expire")
    sub.add_parser("simulate")
    sub.add_parser("restart-before")
    sub.add_parser("restart-after")
    sub.add_parser("commit-failure")

    args = parser.parse_args()
    lab = Lab(args.host, args.port, args.api, args.timeout)
    if args.scenario == "contend":
        scenario_contend(lab)
    elif args.scenario == "race":
        scenario_race(lab, args.clients)
    elif args.scenario == "expire":
        scenario_expire(lab)
    elif args.scenario == "simulate":
        scenario_simulate(lab)
    elif args.scenario == "restart-before":
        scenario_restart_before(lab, args.state)
    elif args.scenario == "restart-after":
        scenario_restart_after(lab, args.state)
    elif args.scenario == "commit-failure":
        scenario_commit_failure(lab)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
