# import socket

# def grab_telnet_banner(host, port=23, timeout=10):
#     try:
#         # 소켓 생성 및 연결
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.settimeout(timeout)
#         sock.connect((host, port))
        
#         # 서버로부터 수신받은 배너 정보 출력
#         banner = sock.recv(1024)
#         print(f"Telnet Banner from {host}:")
#         print(banner.decode('utf-8'))
        
#     except Exception as e:
#         print(f"Error: {e}")
#     finally:
#         sock.close()

# # 사용 예
# host = '192.168.183.129' 
# grab_telnet_banner(host)

import socket
import telnetlib
import errno

def scan_telnet_port(host, port=23, timeout=3):
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

def grab_telnet_banner(host, port=23, timeout=5):
    try:
        tn = telnetlib.Telnet(host,port,timeout)
        banner = tn.read_until(b"\r\n", timeout).decode('utf-8')
        tn.close()
        print(f"Telnet Banner:", {banner})
    except Exception as e:
        print(f"Error grabbing banner: {e}")

# 사용 예
host = '192.168.183.129'  # 검사할 호스트 주소
scan_telnet_port(host)
grab_telnet_banner(host)