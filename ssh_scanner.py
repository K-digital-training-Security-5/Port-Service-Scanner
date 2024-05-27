import socket
import errno

def scan_ssh_port(host, port=22, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"{host}:{port} - Open")
        elif result == errno.ECONNREFUSED:
            print(f"{host}:{port} - Closed")
    except socket.timeout:
        print(f"{host}:{port} - Filtered")
    except socket.error as e:
        print(f"{host}:{port} 포트 검사 중 에러 발생: {e}")
    finally:
        sock.close()

def grab_ssh_banner(host, port=22, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024)  # 서버로부터 초기 응답 받기
        print("SSH Banner:", banner.decode().strip())
    except Exception as e:
        print(f"Error grabbing banner: {e}")
    finally:
        sock.close()

# 사용 예
host = '192.168.183.129'  # 검사할 호스트 주소
scan_ssh_port(host)
grab_ssh_banner(host)
