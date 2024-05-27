import socket

HTTP_PORT = 80

def check_http_service(host):
    try:
        # 소켓 생성
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 소켓 타임아웃 설정
        sock.settimeout(5)
        
        # HTTP 서버에 연결 시도
        sock.connect((host, HTTP_PORT))

        # 연결에 성공하면 HTTP 서비스가 활성화되어 있다는 메시지 출력
        print(f"HTTP service is active on {host}.")

        # 유효한 HTTP 요청을 보내기
        request = b"GET / HTTP/1.1\r\nHost: " + host.encode('utf-8') + b"\r\n\r\n"
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
    
    except ConnectionRefusedError:
        # 연결이 거부된 경우
        print(f"Connection to port {HTTP_PORT} was refused.")
    except socket.timeout:
        # 타임아웃이 발생한 경우
        print("Timeout occurred while waiting for HTTP banner.")
    except Exception as e:
        # 그 외 예외 발생 시
        print(f"Error checking HTTP service: {e}")
    finally:
        # 소켓 닫기 (연결 종료)
        sock.close()

if __name__ == "__main__":
    target_host = input("Enter the target hostname or IP address: ")
    
    # HTTP 서비스 확인 시작 메시지 출력
    print(f"Checking HTTP service for {target_host}...")
    
    # HTTP 서비스 확인 함수 호출
    check_http_service(target_host)
