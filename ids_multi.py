import socket
import datetime
import threading
from collections import defaultdict
from time import sleep

connection_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
TIME_WINDOW = 10  # 초 단위
lock = threading.Lock()

def monitor_port(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', port))
    server_socket.listen(5)
    print(f"{port} 포트에서 포트 스캔을 모니터링합니다...")

    while True:
        client_socket, addr = server_socket.accept()
        ip = addr[0]
        now = datetime.datetime.now()
        print(f"{port} 포트로 {now}에 연결 시도가 있었습니다.")

        with lock:
            connection_attempts[ip].append(now)
            connection_attempts[ip] = [
                time for time in connection_attempts[ip]
                if (now - time).seconds <= TIME_WINDOW
            ]
            #print(f"현재 {ip}의 연결 시도 기록: {connection_attempts[ip]}")

            # if len(connection_attempts[ip]) >= MAX_ATTEMPTS:
            #     print(f"{ip} 로부터 {port} 포트로 {now}에 연결 시도가 있었습니다.")
            #     #print(f"주의: {ip}에서 {port} 포트로 포트 스캔이 감지되었습니다!")
            #     connection_attempts[ip].clear()

        client_socket.close()

def reset_counter():
    while True:
        sleep(TIME_WINDOW)
        with lock:
            now = datetime.datetime.now()
            for ip in list(connection_attempts):
                connection_attempts[ip] = [
                    time for time in connection_attempts[ip]
                    if (now - time).seconds <= TIME_WINDOW
                ]
                if not connection_attempts[ip]:
                    del connection_attempts[ip]

if __name__ == "__main__":
    ports = [21, 22, 23, 25, 53, 110, 143, 443, 445, 3306, 27017,80]
    threads = []
    threading.Thread(target=reset_counter, daemon=True).start()
    for port in ports:
        thread = threading.Thread(target=monitor_port, args=(port,), daemon=True)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()