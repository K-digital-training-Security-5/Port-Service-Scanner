import socket
import errno

def scan_ftp_port(host, port=21, timeout=1):
    #print("스캐닝 시작")  # 스캐닝 시작 로그
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        #print(f"{host}:{port}에 연결 시도 중...")  # 연결 시도 로그
        result = sock.connect_ex((host, port))
        #print(f"연결 결과 코드: {result}")  # 연결 결과 코드 로깅
        if result == 0:
            print("Open")
        elif result == errno.ECONNREFUSED:
            print("Closed")
    except socket.timeout:
        print( "Filtered")
    except socket.error as e:
        print(f"{host}:{port} 포트 검사 중 에러 발생: {e}")
    finally:
        sock.close()
        #print("소켓 닫힘")  # 소켓이 닫히는 것 확인

def grab_ftp_banner(host, port=21, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            banner = sock.recv(1024).decode().strip()  # 서버로부터 받은 배너 메시지
            return banner
    except Exception as e:
        print(f"{host}:{port} 배너 그래빙 중 에러: {e}")
        return None

def scan_ftp_port_with_banner(host, port=21):
    banner = grab_ftp_banner(host, port)
    if banner:
        print(f"{host}:{port} 포트에 FTP 서비스가 활성화되어 있습니다. 배너: {banner}")
    else:
        print(f"{host}:{port} 포트에 FTP 서비스가 없거나 배너를 가져올 수 없습니다.")

host = '192.168.183.129'
scan_ftp_port(host)
scan_ftp_port_with_banner(host)