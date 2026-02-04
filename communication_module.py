#!/usr/bin/env python3
"""
Communication Module - Named Networks Framework
UDP-based communication with fixed port allocation
Fixes the TCP/UDP inconsistency and port confusion issues
"""

import socket
import threading
import queue
import time
from typing import Callable, Optional

# Import network config for default host
try:
    from network_config import DEFAULT_HOST
    _DEFAULT_HOST = DEFAULT_HOST
except ImportError:
    _DEFAULT_HOST = "127.0.0.1"

class CommunicationModule:
    """
    Communication Module implementing UDP producer-consumer architecture
    Full clean replacement
    """

    def __init__(self, node_name: str, host: str = None, port: int = 0):
        self.node_name = node_name
        self.host = host if host is not None else _DEFAULT_HOST
        self.port = port
        self.running = False

        self.server_socket: Optional[socket.socket] = None
        self.receive_buffer = queue.Queue(maxsize=100)
        self.send_buffer = queue.Queue(maxsize=100)
        self.receive_thread: Optional[threading.Thread] = None
        self.process_thread: Optional[threading.Thread] = None
        self.send_thread: Optional[threading.Thread] = None
        self.packet_handler: Optional[Callable] = None
        self.logger = None
        self.stats = {"packets_received": 0, "packets_sent": 0, "errors": 0, "buffer_overflows": 0}

        print(f"[{self.node_name}][COMM] Communication Module initialized (UDP)")

    def set_packet_handler(self, handler: Callable):
        self.packet_handler = handler
        print(f"[{self.node_name}][COMM] Packet handler registered")

    def set_logger(self, logger):
        self.logger = logger
        print(f"[{self.node_name}][COMM] PacketLogger attached")

    def start(self):
        if self.running:
            return
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        if self.port == 0:
            self.port = self.server_socket.getsockname()[1]
        self.running = True
        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.process_thread = threading.Thread(target=self._process_buffer, daemon=True)
        self.send_thread = threading.Thread(target=self._send_buffer_processor, daemon=True)
        self.receive_thread.start()
        self.process_thread.start()
        self.send_thread.start()
        print(f"[{self.node_name}][COMM] Started on {self.host}:{self.port} (UDP)")

    def stop(self):
        print(f"[{self.node_name}][COMM] Stopping Communication Module...")
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        for thread in [self.receive_thread, self.process_thread, self.send_thread]:
            if thread:
                thread.join(timeout=1.0)
        print(f"[{self.node_name}][COMM] Stopped")

    def _receive_loop(self):
        print(f"[{self.node_name}][COMM] Receive thread started (UDP)")
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                data, addr = self.server_socket.recvfrom(65536)
                if data:
                    try:
                        self.receive_buffer.put_nowait((data, addr))
                        self.stats["packets_received"] += 1
                        try:
                            import json
                            pkt = json.loads(data.decode('utf-8', errors='ignore'))
                            pkt_type = pkt.get('type', '').upper()
                            pkt_name = pkt.get('name', '')
                        except Exception:
                            pkt = None
                            pkt_type = 'UNKNOWN'
                            pkt_name = ''
                        if self.logger and pkt is not None:
                            try:
                                self.logger.log('RECV', pkt_type, pkt, addr)
                            except Exception as _e:
                                print(f"[{self.node_name}][COMM] PacketLogger RECV failed: {_e}")
                        # Only log non-fragment packets to console to reduce noise
                        if ':[' not in pkt_name:
                            print(f"[{self.node_name}][COMM] Received packet from {addr} ({len(data)} bytes)")
                    except queue.Full:
                        self.stats["buffer_overflows"] += 1
                        print(f"[{self.node_name}][COMM] Receive buffer overflow! Packet dropped from {addr}")
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.stats["errors"] += 1
                    print(f"[{self.node_name}][COMM] Receive error: {e}")
        print(f"[{self.node_name}][COMM] Receive thread stopped")

    def _process_buffer(self):
        print(f"[{self.node_name}][COMM] Process thread started")
        while self.running:
            try:
                packet_data, source_addr = self.receive_buffer.get(timeout=1.0)
                packet_str = packet_data.decode('utf-8', errors='ignore')
                if self.packet_handler:
                    try:
                        response = self.packet_handler(packet_str, f"{source_addr[0]}:{source_addr[1]}")
                        if response:
                            self.send(response, source_addr[0], source_addr[1])
                    except Exception as e:
                        self.stats["errors"] += 1
                        print(f"[{self.node_name}][COMM] Handler error: {e}")
            except queue.Empty:
                continue
            except Exception as e:
                if self.running:
                    self.stats["errors"] += 1
                    print(f"[{self.node_name}][COMM] Processing error: {e}")
        print(f"[{self.node_name}][COMM] Process thread stopped")

    def _send_buffer_processor(self):
        print(f"[{self.node_name}][COMM] Send thread started")
        while self.running:
            try:
                packet, host, port = self.send_buffer.get(timeout=1.0)
                try:
                    import json
                    pkt = json.loads(packet)
                    pkt_type = pkt.get('type', '').upper()
                    pkt_name = pkt.get('name', '')
                except Exception:
                    pkt = None
                    pkt_type = 'UNKNOWN'
                    pkt_name = ''
                try:
                    if self.server_socket:
                        self.server_socket.sendto(packet.encode('utf-8'), (host, port))
                    else:
                        tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        tmp.sendto(packet.encode('utf-8'), (host, port))
                        tmp.close()
                    self.stats["packets_sent"] += 1
                    if self.logger and pkt is not None:
                        try:
                            self.logger.log('SEND', pkt_type, pkt, (host, port))
                        except Exception as _e:
                            print(f"[{self.node_name}][COMM] PacketLogger SEND failed: {_e}")
                    # Only log non-fragment packets to console to reduce noise
                    if ':[' not in pkt_name:
                        print(f"[{self.node_name}][COMM] Sent packet to {host}:{port}")
                except Exception as e:
                    self.stats["errors"] += 1
                    print(f"[{self.node_name}][COMM] Send error to {host}:{port}: {e}")
            except queue.Empty:
                continue
            except Exception as e:
                if self.running:
                    self.stats["errors"] += 1
                    print(f"[{self.node_name}][COMM] Send buffer error: {e}")
        print(f"[{self.node_name}][COMM] Send thread stopped")
    
    def send(self, packet: str, host: str, port: int):
        """Queue packet for sending (non-blocking)"""
        try:
            self.send_buffer.put_nowait((packet, host, port))
        except queue.Full:
            self.stats["buffer_overflows"] += 1
            print(f"[{self.node_name}][COMM] Send buffer overflow! Packet to {host}:{port} dropped")
    
    def send_packet_sync(self, host: str, port: int, packet_data: str, timeout: float = 5.0) -> Optional[str]:
        """
        Send packet synchronously and wait for response (for client use)
        Uses UDP with consistent port behavior
        """
        from datetime import datetime
        client_socket = None
        try:
            # Create UDP socket for request-response
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Bind to loopback interface explicitly for local communication
            bind_addr = '127.0.0.1' if host in ('127.0.0.1', 'localhost') else '0.0.0.0'
            client_socket.bind((bind_addr, 0))
            local_addr = client_socket.getsockname()
            
            # Set timeout for blocking recvfrom
            client_socket.settimeout(timeout)
            
            # Send packet
            ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            client_socket.sendto(packet_data.encode('utf-8'), (host, port))
            self.stats["packets_sent"] += 1
            try:
                import json
                pkt = json.loads(packet_data)
                pkt_type = pkt.get('type','').upper()
                if self.logger:
                    try:
                        self.logger.log('SEND', pkt_type, pkt, (host, port))
                    except Exception:
                        print(f"[{self.node_name}][COMM] Logger send failed")
            except Exception:
                pass

            print(f"[{ts}][{self.node_name}][COMM] Sent packet from {local_addr} to {host}:{port}")
            
            # Wait for response (blocking with timeout)
            ts2 = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            print(f"[{ts2}][{self.node_name}][COMM] Waiting for response on {local_addr}...")
            try:
                response_data, addr = client_socket.recvfrom(65536)
                ts3 = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                print(f"[{ts3}][{self.node_name}][COMM] Received response from {addr}")
            except socket.timeout:
                ts_timeout = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                print(f"[{ts_timeout}][{self.node_name}][COMM] TIMEOUT after {timeout}s waiting for response from {host}:{port} (local socket was {local_addr})")
                return None
            except ConnectionResetError:
                print(f"[{self.node_name}][COMM] Connection reset - no server at {host}:{port}")
                return None
            except OSError as ose:
                if ose.errno == 10054:
                    print(f"[{self.node_name}][COMM] No server listening at {host}:{port}")
                    return None
                raise
            
            self.stats["packets_received"] += 1
            try:
                import json
                pkt_resp = json.loads(response_data.decode('utf-8', errors='ignore'))
                pkt_type_resp = pkt_resp.get('type','').upper()
                pkt_name = pkt_resp.get('name', 'unknown')
                if self.logger:
                    try:
                        self.logger.log('RECV', pkt_type_resp, pkt_resp, addr)
                    except Exception:
                        print(f"[{self.node_name}][COMM] Logger recv failed")
                print(f"[{self.node_name}][COMM] Sync recv: {pkt_type_resp} {pkt_name}")
            except Exception:
                print(f"[{self.node_name}][COMM] Sync recv: {len(response_data)} bytes from {addr}")
            
            return response_data.decode('utf-8', errors='ignore')
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[{self.node_name}][COMM] Send-receive error: {e}")
            return None
        finally:
            try:
                if client_socket:
                    client_socket.close()
            except Exception:
                pass

    def send_and_wait(self, packet: str, host: str, port: int, timeout: float = 5.0) -> Optional[str]:
        """Send packet and wait for response using a dedicated sync socket.
        
        Creates a new socket for this request-response cycle but handles
        Windows UDP quirks by using proper socket options.
        
        Returns response string or None on timeout/error.
        """
        from datetime import datetime
        sync_socket = None
        
        try:
            ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            
            # Create dedicated socket for this request
            sync_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Important: Set socket options BEFORE binding
            sync_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to loopback for local communication
            bind_addr = '127.0.0.1' if host in ('127.0.0.1', 'localhost') else '0.0.0.0'
            sync_socket.bind((bind_addr, 0))
            local_addr = sync_socket.getsockname()
            
            # Set timeout
            sync_socket.settimeout(timeout)
            
            # Send packet
            sync_socket.sendto(packet.encode('utf-8'), (host, port))
            self.stats["packets_sent"] += 1
            print(f"[{ts}][{self.node_name}][COMM] Sync send from {local_addr} to {host}:{port}")
            
            # Wait for response
            try:
                data, addr = sync_socket.recvfrom(65536)
                ts2 = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                print(f"[{ts2}][{self.node_name}][COMM] Sync recv from {addr}: {len(data)} bytes")
                self.stats["packets_received"] += 1
                return data.decode('utf-8', errors='ignore')
            except socket.timeout:
                ts_timeout = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                print(f"[{ts_timeout}][{self.node_name}][COMM] TIMEOUT after {timeout}s from {host}:{port}")
                return None
            except ConnectionResetError:
                print(f"[{self.node_name}][COMM] Connection reset from {host}:{port}")
                return None
            except OSError as e:
                if e.errno == 10054:  # Windows: Connection forcibly closed
                    print(f"[{self.node_name}][COMM] No server at {host}:{port}")
                    return None
                raise
                
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[{self.node_name}][COMM] send_and_wait error: {e}")
            import traceback
            traceback.print_exc()
            return None
        finally:
            if sync_socket:
                try:
                    sync_socket.close()
                except:
                    pass

    def send_immediate(self, packet: str, host: str, port: int) -> bool:
        """Send packet immediately using the bound server socket (bypassing send queue).

        Returns True on success, False on any failure.
        """
        try:
            # Prefer bound socket to preserve source port
            if self.server_socket:
                self.server_socket.sendto(packet.encode('utf-8'), (host, port))
            else:
                tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                tmp.sendto(packet.encode('utf-8'), (host, port))
                tmp.close()

            self.stats["packets_sent"] += 1
            print(f"[{self.node_name}][COMM] Immediately sent packet to {host}:{port}")
            return True
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[{self.node_name}][COMM] Immediate send error to {host}:{port}: {e}")
            return False

    def get_port(self) -> int:
        """Get the actual port being used"""
        return self.port
    
    def get_stats(self) -> dict:
        """Get communication statistics"""
        return self.stats.copy()
    
    def get_buffer_status(self):
        """Get current buffer status"""
        return {
            'receive_buffer_size': self.receive_buffer.qsize(),
            'send_buffer_size': self.send_buffer.qsize(),
            'max_buffer_size': 100
        }


# Test the UDP module
if __name__ == "__main__":
    print("Testing UDP Communication Module")
    
    # Create test module
    comm = CommunicationModule("TestNode", port=8888)
    
    # Simple handler
    def test_handler(packet, source):
        print(f"Received from {source}: {packet[:50]}...")
        return "ACK: UDP packet received"
    
    comm.set_packet_handler(test_handler)
    comm.start()
    
    print(f"UDP server listening on port {comm.get_port()}")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            time.sleep(1)
            stats = comm.get_stats()
            if stats['packets_received'] > 0 or stats['packets_sent'] > 0:
                print(f"Stats: RX={stats['packets_received']}, TX={stats['packets_sent']}, Errors={stats['errors']}")
    except KeyboardInterrupt:
        print("\nStopping...")
        comm.stop()