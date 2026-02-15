import socket
import threading
import time
import struct

# CONFIGURATION
PORTS = [9997, 9998, 9999] 
STALL_DELAY = 0.400 # 400ms

class DeterministicHandler:
    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", port))
        self.history = {} 
        self.lock = threading.Lock()

    def is_bad_packet(self, req_id):
        # 2% of packets are bad.
        # IDs ending in 00 or 01 are bad.
        # all the different servers will have the same bad packets 
        return (req_id % 100) < 2

    def process(self, addr, data):
        if len(data) < 4: return
        req_id = struct.unpack('I', data[0:4])[0]
        
        delay = 0.002 # Fast path
        
        if self.is_bad_packet(req_id):
            with self.lock:
                now = time.time()
                # check history (TTL 1.0s)
                if req_id in self.history and (now - self.history[req_id] < 1.0):
                    # HEDGE DETECTED: we saw this recently! Don't hedge again.
                    pass 
                else:
                    # FIRST SIGHT: stall it.
                    delay = STALL_DELAY
                    self.history[req_id] = now
        
        time.sleep(delay)
        try:
            self.sock.sendto(data, addr)
        except:
            pass

    def start(self):
        print(f"[*] Port {self.port} Active")
        while True:
            data, addr = self.sock.recvfrom(1024)
            threading.Thread(target=self.process, args=(addr, data)).start()

if __name__ == "__main__":
    print("=== SERVER ===")
    for p in PORTS:
        t = threading.Thread(target=lambda: DeterministicHandler(p).start())
        t.daemon = True
        t.start()
    while True: time.sleep(1)
