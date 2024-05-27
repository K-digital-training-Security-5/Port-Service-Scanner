import socket

def check_dns_port(host):
    try:
        # 소켓 생성 (tcp)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 소켓 타임아웃 설정
        sock.settimeout(5)
        
        # 포트 53에 연결 시도
        result = sock.connect_ex((host, 53))

        if result == 0:
            print(f"Port 53 is open on {host}")
        else:
            print(f"Port 53 is closed on {host}")
        
    except Exception as e:
        # 예외 발생 시
        print(f"Error checking port 53 on {host}: {e}")
    finally:
        # 소켓 닫기 (연결 종료)
        sock.close()

if __name__ == "__main__":
    target_host = input("Enter the target IP address: ")
    
    # 포트 확인 시작 메시지 출력
    print(f"Checking port 53 for {target_host}...")
    
    # 포트 확인 함수 호출
    check_dns_port(target_host)
