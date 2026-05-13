import discord
import asyncio
import os
import subprocess
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
DISCORD_CHANNEL_ID = int(os.getenv("DISCORD_CHANNEL_ID", "0"))

BLOCKED_IPS = {}
PENDING_BLOCKS = {}

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

def block_ip(ip):
    try:
        subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            capture_output=True, text=True
        )
        BLOCKED_IPS[ip] = {
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "reason": "auto-block after CRITICAL score"
        }
        return True
    except Exception as e:
        print(f"[BLOCKER ERROR] {e}")
        return False

def unblock_ip(ip):
    try:
        subprocess.run(
            ["sudo", "ufw", "delete", "deny", "from", ip],
            capture_output=True, text=True
        )
        if ip in BLOCKED_IPS:
            del BLOCKED_IPS[ip]
        return True
    except Exception as e:
        print(f"[BLOCKER ERROR] {e}")
        return False

async def send_block_request(ip, username, score):
    await client.wait_until_ready()
    channel = client.get_channel(DISCORD_CHANNEL_ID)
    if not channel:
        print(f"[BOT ERROR] Channel not found — ID: {DISCORD_CHANNEL_ID}")
        print(f"[BOT ERROR] Available channels:")
        for guild in client.guilds:
            for ch in guild.channels:
                print(f"  - {ch.name} : {ch.id}")
        return

    embed = discord.Embed(
        title="🚨 CRITICAL Alert — Block Request",
        description=f"IP `{ip}` has reached a CRITICAL risk score.",
        color=0xFF0000
    )
    embed.add_field(name="Source IP", value=ip or "N/A", inline=True)
    embed.add_field(name="Username", value=username or "N/A", inline=True)
    embed.add_field(name="Risk Score", value=str(score), inline=True)
    embed.add_field(
        name="Action Required",
        value=f"Reply `!block {ip}` to block\nReply `!ignore` to ignore",
        inline=False
    )
    embed.set_footer(text="SIEM-PME Auto-Response System")
    embed.timestamp = datetime.now(timezone.utc)

    await channel.send(embed=embed)
    PENDING_BLOCKS[ip] = {
        "username": username,
        "score": score,
        "requested_at": datetime.now(timezone.utc).isoformat()
    }

@client.event
async def on_ready():
    print(f"[BOT] SIEM-PME Bot connected as {client.user}")
    print(f"[BOT] Looking for channel ID: {DISCORD_CHANNEL_ID}")
    for guild in client.guilds:
        print(f"[BOT] Server: {guild.name}")
        for channel in guild.channels:
            print(f"  - {channel.name} : {channel.id}")

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    if message.content.startswith("!block"):
        content = message.content[len("!block"):].strip()
        if content:
            ip = content
        elif PENDING_BLOCKS:
            ip = list(PENDING_BLOCKS.keys())[-1]
        else:
            await message.channel.send("❌ No pending block request found.")
            return

        if block_ip(ip):
            await message.channel.send(
                f"✅ IP `{ip}` has been blocked successfully.\n"
                f"Use `!unblock {ip}` to reverse this action."
            )
            if ip in PENDING_BLOCKS:
                del PENDING_BLOCKS[ip]
        else:
            await message.channel.send(f"❌ Failed to block IP `{ip}`.")

    elif message.content.startswith("!unblock"):
        parts = message.content.split()
        if len(parts) < 2:
            await message.channel.send("Usage: `!unblock <ip>`")
            return
        ip = parts[1]
        if unblock_ip(ip):
            await message.channel.send(f"✅ IP `{ip}` has been unblocked.")
        else:
            await message.channel.send(f"❌ Failed to unblock IP `{ip}`.")

    elif message.content == "!blocked":
        if not BLOCKED_IPS:
            await message.channel.send("✅ No IPs currently blocked.")
        else:
            blocked_list = "\n".join([f"`{ip}` — blocked at {info['blocked_at']}"
                                     for ip, info in BLOCKED_IPS.items()])
            await message.channel.send(f"🔒 **Blocked IPs:**\n{blocked_list}")

    elif message.content == "!ignore":
        if PENDING_BLOCKS:
            ip = list(PENDING_BLOCKS.keys())[-1]
            del PENDING_BLOCKS[ip]
            await message.channel.send(f"⚠️ Block request for `{ip}` ignored.")
        else:
            await message.channel.send("No pending block request.")

    elif message.content == "!help":
        help_text = (
            "**SIEM-PME Bot Commands:**\n"
            "`!block <ip>` — Block an IP address\n"
            "`!unblock <ip>` — Unblock an IP address\n"
            "`!blocked` — List all blocked IPs\n"
            "`!ignore` — Ignore the latest block request\n"
            "`!help` — Show this help message"
        )
        await message.channel.send(help_text)

def run_bot():
    client.run(DISCORD_BOT_TOKEN)

if __name__ == "__main__":
    run_bot()
