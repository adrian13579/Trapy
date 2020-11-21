from trapy import dial, send, close  # noqa: F403

hello_world = 'Hello world'

# file_path = '/home/andy/Documents/3ro/Redes/trapy/trapy/A.txt'
file_path = '/mnt/69F79531507E7A36/CS/Others/Redes/Proyecto/trapy/trapy/file_to_send/a.pdf'
# file_path = '/home/andy/Documents/3ro/Redes/trapy/test_files/pokemonHeartGold.rar'
chunk_size = 8196


# chunk_size = 64
def chunked_file(file_path, chunk_size):
    file = open(file_path, 'rb')
    data = file.read(-1)
    chunks = []
    if len(data) % chunk_size == 0:
        chunks_count = len(data) / chunk_size
    else:
        chunks_count = len(data) // chunk_size
        chunks_count += 1
    for i in range(chunks_count):
        if i == chunks_count - 1:
            chunks.append(data[i * chunk_size:])
        else:
            chunks.append(data[i * chunk_size: i * chunk_size + chunk_size])
    # print(f'chunks {chunks}')
    return chunks


# conn = dial('127.0.0.1:4545')
conn = dial('10.0.0.2:4545')
# conn = dial('192.168.43.156:4545')
# conn = dial('192.168.43.190:4545')
# exit()
for chunk in chunked_file(file_path, chunk_size):
    # print(f'calling send with {chunk}')
    send(conn, chunk)
close(conn)
print('conn closed')
