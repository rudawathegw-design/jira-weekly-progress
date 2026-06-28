"""
clear_queue.py
Remove successfully-posted items from the comment queue.

Run AFTER post_comments.py and AFTER the workflow has synced to the latest
origin/main. It drops exactly the keys post_comments recorded in
data/temp/posted_keys.json — a safe read-modify-write so that items queued
concurrently (after this run started) are never clobbered, and failed items
remain in the queue for the next attempt.
"""
import os
import sys
import json

ROOT             = os.path.join(os.path.dirname(__file__), "..")
QUEUE_PATH       = os.path.join(ROOT, "data", "comment_queue.json")
POSTED_KEYS_PATH = os.path.join(ROOT, "data", "temp", "posted_keys.json")


def run():
    if not os.path.exists(POSTED_KEYS_PATH):
        print("No posted-keys file — nothing to clear.")
        return
    try:
        posted = set(json.load(open(POSTED_KEYS_PATH, encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        posted = set()
    if not posted:
        print("No posted keys recorded — nothing to clear.")
        return

    from crypto_store import load_store, save_store
    queue = load_store(QUEUE_PATH, default=None)
    if not queue:
        print("No queue present — nothing to clear.")
        return

    items = queue.get("items") or []
    remaining = [it for it in items if (it.get("key") or "").strip() not in posted]
    if len(remaining) == len(items):
        print(f"None of the {len(posted)} posted key(s) are still in the queue — no change.")
        return

    queue["items"] = remaining
    save_store(QUEUE_PATH, queue)
    print(f"Cleared {len(items) - len(remaining)} posted item(s); {len(remaining)} remain in queue.")


if __name__ == "__main__":
    try:
        run()
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)
