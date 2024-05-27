from impacket.smbconnection import SMBConnection
import telnetlib
import socket
import ssl
import struct
import errno

def create_socket(target_ip,port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_ip, port))
        return sock
    except socket.timeout:
        print(f"Port {port} is filtered (timeout)")
        return None
    except ConnectionRefusedError:
        print(f"Port {port} is closed (connection refused)")
        return None
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return None
        
def check_mongodb_port(target_ip, port=27017):
    sock = create_socket(target_ip, port)
    if sock is None:
        return

    try:
        # MongoDB에 서버 상태를 요청하는 명령어 전송
        message = b'\x3a\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x01\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10buildinfo\x00\x01\x00\x00\x00\x00'
        sock.send(message)
        response = sock.recv(1024)
        print("MongoDB Banner:", response.decode('utf-8', errors='ignore'))
    finally:
        sock.close()

def check_mysql_port(target_ip,port):
    sock = create_socket(target_ip, port)
    if sock is None:
        return
    try:
        response = sock.recv(1024)
        print("MySQL Banner:", response.decode('utf-8', errors='ignore'))
    finally:
        sock.close()

def check_dns_port(target_ip,port):
        sock = create_socket(target_ip, port)
        if sock:
            print(f"DNS port 53 is open on {target_ip}")
            sock.close()
    
def check_http_port(target_ip,port):
        with create_socket(target_ip,port) as sock:

            # 연결에 성공하면 HTTP 서비스가 활성화되어 있다는 메시지 출력
            print(f"HTTP service is active on {target_ip}.")

            # 유효한 HTTP 요청을 보내기
            request = b"GET / HTTP/1.1\r\nHost: " + target_ip.encode('utf-8') + b"\r\n\r\n"
            sock.sendall(request)

            # 서버로부터 받은 데이터를 읽어옴
            response_headers = b""
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                response_headers += data
                if b"\r\n\r\n" in response_headers:
                    break

            # 받아온 헤더 정보 출력
            print(f"HTTP banner:\n{response_headers.decode('utf-8').split('\r\n\r\n')[0]}")

def check_smtp_port(target_ip,port):
    sock = create_socket(target_ip, port)
    if sock is None:
        return
    
    try:
        response = sock.recv(1024).decode('utf-8').strip()
        
            # 받아온 배너 정보 출력
        print(f"SMTP service banner: {response}")
    finally:
        sock.close()

def check_ftp_port(target_ip,port):
    sock = create_socket(target_ip, port)
    if sock is None:
        return
    
    try:
        response = sock.recv(1024).decode().strip() 
            # 받아온 배너 정보 출력
        print(f"FTP service banner: {response}")
    finally:
        sock.close()

def check_ssh_port(target_ip,port):
    sock = create_socket(target_ip, port)
    if sock is None:
        return
    
    try:
        response = sock.recv(1024)
            # 받아온 배너 정보 출력
        print(f"SSH service banner: {response}")
    finally:
        sock.close()
    
def check_pop3_port(target_ip,port):
    sock = create_socket(target_ip, port)
    if sock is None:
        return
    try:
        sock.send(b"USER\r\n")
        response = sock.recv(1024)
        print("POP3 Banner:", response.decode('utf-8', errors='ignore'))
    finally:
        sock.close()

def check_IMAP_port(target_ip,port):
    sock = create_socket(target_ip,port)
    if sock is None:
        return
    try:
        response = sock.recv(4096)
        print("IMAP Banner:", response.decode('utf-8', errors='ignore'))
    finally:
        sock.close()

def check_https_port(target_ip,port):
    sock =create_socket(target_ip,port)
    if sock is None:
        return
    try:
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=target_ip)
        sock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
        response = sock.recv(4096)
        print("https Banner:", response.decode('utf-8', errors='ignore'))
    finally:
        sock.close()

def check_smb_port(target_ip,port):
    try:
        conn = SMBConnection(target_ip, sess_port=port)
        print("Connected to: ", target_ip)
        print("Server name: ", conn.getServerName())
        print("Server domain: ", conn.getServerDomain())
        print("OS: ", conn.getServerOS())
        conn.close()
    except Exception as e:
        print("Failed to connect: ", str(e))

def check_telnet_port(target_ip,port,timeout =3):
    try:
        tn = telnetlib.Telnet(target_ip,port,timeout)
        response = tn.read_until(b"\r\n", timeout).decode('utf-8')
        tn.close()
        print(f"Telnet Banner:", {response})
    except Exception as e:
        print(f"Error grabbing banner: {e}")

def check_all_port(target_ip):
    check_ftp_port(target_ip,21)#포트 21 ftp
    check_ssh_port(target_ip,22)#포트 22 ssh
    check_telnet_port(target_ip,23)#포트 23 telnet
    check_smtp_port(target_ip,25)#포트 25 smtp
    check_dns_port(target_ip,53)#포트 53 dns
    check_http_port(target_ip,80)#포트 80 http
    check_pop3_port(target_ip,110) #포트 110 pop3
    check_IMAP_port(target_ip,143)#포트 143 IMAP
    check_https_port(target_ip,443)#포트 443 https
    check_smb_port(target_ip,445)#포트 445 smb
    check_mysql_port(target_ip,3306)#포트 3306 mysql
    check_mongodb_port(target_ip,27017)#포트 27017 mongodb
    

if __name__ == "__main__":
    target_ip = "127.0.0.1"
    
    # 포트 확인 시작 메시지 출력
    print(f"Checking port for {target_ip}...")
    
    # 포트 확인 함수 호출
    check_all_port(target_ip)