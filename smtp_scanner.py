import socket

# SMTP 포트 번호
SMTP_PORT = 25

# SMTP 서비스 확인 함수
def check_smtp_service(host):
    try:
        # 소켓 생성
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 소켓 타임아웃 설정
        sock.settimeout(5)
        
        # SMTP 서버에 연결 시도
        sock.connect((host, SMTP_PORT))

        # SMTP 서버로부터 배너 정보 받아오기
        banner = sock.recv(1024).decode('utf-8').strip()
        
        # 받아온 배너 정보 출력
        print(f"SMTP service banner: {banner}")

    except ConnectionRefusedError:
        # 연결이 거부된 경우
        print(f"Connection to port {SMTP_PORT} was refused.")
    except Exception as e:
        # 그 외 예외 발생 시
        print(f"Error checking SMTP service: {e}")
    finally:
        # 소켓 닫기 (연결 종료)
        sock.close()

if __name__ == "__main__":
    target_host = input("Enter the target hostname or IP address: ")
    
    # SMTP 서비스 확인 시작 메시지 출력
    print(f"Checking SMTP service for {target_host}...")
    
    # SMTP 서비스 확인 함수 호출
    check_smtp_service(target_host)