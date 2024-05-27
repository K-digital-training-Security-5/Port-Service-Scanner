import socket
import datetime
import threading
from collections import defaultdict
from time import sleep

# 연결 시도를 추적하는 딕셔너리
connection_attempts = defaultdict(int)

# 탐지 파라미터
MAX_ATTEMPTS = 5
TIME_WINDOW = 10  # 초 단위

def monitor_port(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', port))
    server_socket.listen(5)
    print(f"Monitoring for port scans on port {port}...")

    while True:
        client_socket, addr = server_socket.accept()
        ip = addr[0]
        now = datetime.datetime.now()
        connection_attempts[ip] += 1
        print(f"Connection attempt from {ip} at {now}")

        # 연속된 연결 시도를 감지하는 로직
        if connection_attempts[ip] >= MAX_ATTEMPTS:
            print(f"Potential port scan detected from {ip}!")
            connection_attempts[ip] = 0  # 카운트 리셋

        client_socket.close()

def reset_counter():
    """정해진 시간마다 카운터를 리셋"""
    while True:
        sleep(TIME_WINDOW)
        connection_attempts.clear()

if __name__ == "__main__":
    port = 22  # 모니터링할 포트 번호
    # 카운터 리셋 스레드 시작
    threading.Thread(target=reset_counter, daemon=True).start()
    # 포트 모니터링 스레드 시작
    monitor_port(port)
