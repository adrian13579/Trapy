from trapy import listen, accept, recv, close  # noqa: F403

# __all__ = [
#     'listen',
#     'dial',
#     'accept',
#     'send',
#     'recv',
#     'close',
# ]

# rawData = ""
# d = open('/home/andy/Documents/3ro/Redes/trapy/trapy/stuff.txt')
# for chunk in d:
#     for b in chunk:
#         rawData += b

file_p = '/mnt/69F79531507E7A36/CS/Others/Redes/Proyecto/trapy/trapy/file_recv/a.pdf'
# file_p = '/home/andy/Documents/3ro/Redes/trapy/trapy/written.exe'
try:
    file = open(file_p, 'w')  # para truncar el archivo
    file.close()
    file = open(file_p, 'ab')
except:
    raise Exception('Unable to write to the file')

x = listen('127.0.0.1:4545')
# x = listen('192.168.43.156:4545')

conn = accept(x)
# z = recv(y, 2**16-1)
# exit()
while True:
    z = recv(conn, 2 ** 16 - 1)
    if len(z) == 0:
        print('Broke')
        break
    w = file.write(z)
    print(f'file.write devolvio {w}')

    # print(f'dummy recvd : {z}')

file.close()
close(conn)
print('conn closed')
