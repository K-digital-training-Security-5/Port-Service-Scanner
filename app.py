from flask import Flask, render_template, request
from impacket.smbconnection import SMBConnection
import socket
import telnetlib
import ssl
import concurrent.futures

app = Flask(__name__)

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    27017: "MongoDB",
}

# IP 유효 여부 확인
def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# 포트 스캔 함수
def check_open_ports(host):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(check_service, host, port) for port in PORT_SERVICES]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result['status'] == 'Open':
                open_ports.append(result['port'])
    open_ports.sort()
    return open_ports

def check_service(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))  # 포트 연결 시도
        if result == 0:
            status = "Open"
        else:
            status = "Closed"
            return {
                "port": port,
                "service": PORT_SERVICES.get(port, "Unknown"),
                "status": status,
                "version": None
            }

        if port == 80: # HTTP는 응답 요청 필요해서 따로
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            response = sock.recv(1024).decode('utf-8')
            version = response.split('\r\n')[0]
        elif port == 23:
            tn = telnetlib.Telnet(host, port, timeout=3)
            banner = tn.read_until(b"\r\n", timeout=3).decode('utf-8')
            version = banner.strip()
        elif port == 53: # DNS 포트 (UDP)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            try:
                sock.sendto(b'', (host, port))  # 빈 데이터를 보냅니다.
                status = "Open"
                version = "DNS Service Detected"
            except socket.timeout:
                status = "Closed"
                version = None
        elif port == 443:
            version = "SSL/TLS Handshake Successful"
        elif port == 445:
            conn = SMBConnection(host, sess_port=port)
            version = conn.getServerName(), conn.getServerDomain(), conn.getServerOS()
        elif port == 3306: # MySQL 포트
            try:
                sock.sendall(b"\x00\x00\x00\x0a\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
                banner = sock.recv(1024).decode('latin1').strip()
                version = banner
            except Exception as e:
                version = str(e)
        elif port == 27017: # MongoDB 포트
            try:
                sock.sendall(b'\x3a\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x01\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10buildinfo\x00\x01\x00\x00\x00\x00')
                version = sock.recv(1024).decode('latin1').strip()
            except Exception as e:
                version = str(e)
        else: # 그 외의 포트들
            banner = sock.recv(1024).decode('utf-8').strip()
            version = banner

        return {
            "port": port,
            "service": PORT_SERVICES.get(port, "Unknown"),
            "status": status,
            "version": version
        }
    except socket.timeout:
        return {
            "port": port,
            "service": PORT_SERVICES.get(port, "Unknown"),
            "status": "Open",
            "version": "timeout"
        }
    except Exception as e:
        return {
            "port": port,
            "service": PORT_SERVICES.get(port, "Unknown"),
            "status": "Open",
            "version": str(e)
        }
    finally:
        sock.close()

@app.route("/", methods=["GET", "POST"])
def index():
    target_host = None
    results = []
    open_ports = []
    if request.method == "POST":
        target_host = request.form["target_host"]
        if is_valid_ip(target_host):
            open_ports = check_open_ports(target_host)
            for port in PORT_SERVICES:
                if port not in open_ports:
                    result = {
                        "port": port,
                        "service": PORT_SERVICES.get(port, "Unknown"),
                        "status": "Closed",
                        "version": None
                    }
                    results.append(result)
                else:
                    result = check_service(target_host, port)
                    results.append(result)
    return render_template("index.html", 
                           target_host=target_host, 
                           open_ports=open_ports, 
                           results=results)

if __name__ == "__main__":
    app.run(debug=True)
