#!/usr/bin/env python3
"""Test v2 runtime on .93 standby node via WebSocket API."""
import websocket
import json
import sys

WS_URL = "ws://127.0.0.1:18901/ws"
PASSWORD = "dba@2026"
SESSION_ID = "test-v2-runtime"

def main():
    print("Connecting to gateway...")
    ws = websocket.create_connection(WS_URL)

    # Wait for hello
    hello = ws.recv()
    print("HELLO:", hello[:200])

    # Send connect
    ws.send(json.dumps({
        "id": "connect-1",
        "method": "connect",
        "params": {
            "protocolVersion": 3,
            "password": PASSWORD
        }
    }))
    resp = ws.recv()
    print("CONNECT:", resp[:200])
    data = json.loads(resp)
    if "error" in data:
        print("CONNECT FAILED:", data["error"])
        ws.close()
        return

    # Send chat message
    ws.send(json.dumps({
        "id": "chat-1",
        "method": "chat",
        "params": {
            "sessionId": SESSION_ID,
            "message": "你好，请用一句话介绍你自己"
        }
    }))

    # Collect response
    ws.settimeout(60)
    final_response = None
    try:
        while True:
            r = ws.recv()
            d = json.loads(r)
            msg_type = d.get("type", "")
            payload = d.get("payload", {})
            state = payload.get("state", "")

            if msg_type == "chat" and state == "final":
                final_response = payload.get("text", payload.get("message", ""))
                print("FINAL RESPONSE:", final_response[:500])
                break
            elif "error" in d:
                print("ERROR:", json.dumps(d)[:300])
                break
            elif msg_type == "chat":
                # streaming delta
                delta = payload.get("text", "")
                if delta:
                    print("DELTA:", delta[:100])
            else:
                print("EVENT:", msg_type, str(d)[:150])
    except Exception as e:
        print("TIMEOUT/ERROR:", e)

    ws.close()

    if final_response:
        print("\n=== TEST PASSED: v2 runtime responded ===")
        sys.exit(0)
    else:
        print("\n=== TEST FAILED: no final response ===")
        sys.exit(1)

if __name__ == "__main__":
    main()
