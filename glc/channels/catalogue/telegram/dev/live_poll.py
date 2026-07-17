"""Helper script to test the Telegram adapter live with long-polling.

Requires:
  - TELEGRAM_BOT_TOKEN env variable.
  - A running GLC gateway (uv run glc serve) on port 8111.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys

import httpx

# Load environment
from dotenv import load_dotenv

from glc.channels.catalogue.telegram.adapter import Adapter
from glc.channels.envelope import ChannelReply
from glc.config import require_install_token_from_env
from glc.security.pairing import get_pairing_store

load_dotenv()


async def main() -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        print("Error: TELEGRAM_BOT_TOKEN environment variable not set.")
        print("Please set it in your environment or a .env file.")
        sys.exit(1)

    print("Telegram Live Polling Bridge Starting...")

    # 1. Verify the owner was bootstrapped out of band.
    owner_id = os.getenv("TELEGRAM_OWNER_ID")
    store = get_pairing_store()

    if owner_id:
        owner = store.lookup("telegram", owner_id)
        if owner is not None and owner.trust_level == "owner_paired":
            print(f"Using pre-bootstrapped owner Telegram ID: {owner_id}")
        else:
            print(f"\n[live_poll] TELEGRAM_OWNER_ID {owner_id!r} is not paired as owner.")
            print(f"Run: uv run python scripts/bootstrap_owner.py telegram {owner_id}")
            print("Messages will remain untrusted until setup is completed.")
    else:
        print("\n[live_poll] No TELEGRAM_OWNER_ID set. Messages will remain untrusted.")
        print("Set TELEGRAM_OWNER_ID, then run the installer bootstrap command.")

    # 2. Get Gateway connection details
    gateway_port = int(os.getenv("GLC_PORT", "8111"))
    install_token = require_install_token_from_env()

    # Instantiate the adapter
    adapter = Adapter()

    # WebSocket URL
    ws_url = f"ws://localhost:{gateway_port}/v1/channels/telegram?token={install_token}"

    print(f"Connecting to GLC Gateway WebSocket at: ws://localhost:{gateway_port}/v1/channels/telegram")

    try:
        import websockets
    except ImportError:
        print("Installing websockets library...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "websockets"])
        import websockets

    async with websockets.connect(ws_url) as ws:
        print("Connected to GLC Gateway WebSocket!")
        offset = 0

        async def poll_telegram() -> None:
            nonlocal offset
            async with httpx.AsyncClient() as client:
                while True:
                    try:
                        url = f"https://api.telegram.org/bot{token}/getUpdates"
                        resp = await client.get(url, params={"offset": offset, "timeout": 10}, timeout=15)
                        if resp.status_code == 200:
                            data = resp.json()
                            if data.get("ok"):
                                for update in data["result"]:
                                    offset = update["update_id"] + 1
                                    print(f"Received Telegram Update ID: {update['update_id']}")

                                    # Translate to ChannelMessage
                                    msg = await adapter.on_message(update)
                                    if msg:
                                        print(f"Sending ChannelMessage to gateway: {msg.text}")
                                        await ws.send(msg.model_dump_json())
                                    else:
                                        print("Update dropped (not allowed or no message)")
                        elif resp.status_code == 409:
                            print(
                                "Conflict: another webhook or long poll is running for this bot. Please stop it."
                            )
                            await asyncio.sleep(5)
                        else:
                            print(f"Telegram API getUpdates returned status {resp.status_code}")
                    except Exception as e:
                        print(f"Error polling Telegram: {e}")
                    await asyncio.sleep(1)

        async def receive_from_gateway() -> None:
            while True:
                try:
                    raw_data = await ws.recv()
                    data = json.loads(raw_data)

                    if "error" in data:
                        print(f"Gateway error: {data['error']}")
                        continue

                    reply = ChannelReply.model_validate(data)
                    print(f"Received ChannelReply from gateway: {reply.text}")

                    # Dispatch via adapter
                    sent_info = await adapter.send(reply)
                    print(f"Sent reply to Telegram. API Response: {sent_info}")
                except websockets.exceptions.ConnectionClosed:
                    print("Gateway connection closed.")
                    break
                except Exception as e:
                    print(f"Error receiving from gateway / sending to Telegram: {e}")

        # Run both tasks concurrently
        await asyncio.gather(poll_telegram(), receive_from_gateway())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting.")
