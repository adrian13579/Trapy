from trapy import get_free_port, Conn, path

a = get_free_port(path)
print(a)

conn = Conn()
conn.bind(('', a))
