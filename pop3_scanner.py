import socket
import ssl

def scan_port(host, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            banner = grab_banner(sock, port)
            print(f"Port {port} is open. Banner: {banner}")
    except socket.timeout:
        print(f"Port {port} is filtered (timeout)")
    except ConnectionRefusedError:
        print(f"Port {port} is closed (connection refused)")
    except Exception as e:
        print(f"Error scanning port {port}: {e}")

def grab_banner(sock, port, timeout=2):
    try:
        sock.settimeout(timeout)
        # Start TLS for IMAP and HTTPS
        if port in [993, 443]:  # Adding 443 for HTTPS
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        
        # Send a basic HTTP GET request for HTTPS
        if port == 443:
            sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
        
        banner = sock.recv(4096).decode().strip()  # Increase buffer size if necessary
        return banner
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    host = '192.168.183.135'
    ports = [110, 143, 443]  # POP3, IMAP, HTTPS ports
    for port in ports:
        scan_port(host, port)
