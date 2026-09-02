import argparse
import json
import signal
import socket
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--stats", required=True)
    arguments = parser.parse_args()
    state = {"received_bytes": 0, "received_packets": 0, "sent_bytes": 0, "sent_packets": 0}
    running = True

    def persist(*_):
        nonlocal running
        with open(arguments.stats, "w", encoding="utf-8") as output:
            json.dump(state, output, sort_keys=True)
            output.write("\n")
        running = False

    signal.signal(signal.SIGINT, persist)
    signal.signal(signal.SIGTERM, persist)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 * 1024 * 1024)
    server.bind((arguments.host, arguments.port))
    server.settimeout(0.5)
    while running:
        try:
            packet, address = server.recvfrom(65_535)
        except TimeoutError:
            continue
        state["received_bytes"] += len(packet)
        state["received_packets"] += 1
        if server.sendto(packet, address) == len(packet):
            state["sent_bytes"] += len(packet)
            state["sent_packets"] += 1
    server.close()


if __name__ == "__main__":
    main()
