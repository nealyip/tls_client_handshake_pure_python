def read(conn):
    record_layer = conn.recv(5)

    read_bytes = required_bytes = int.from_bytes(record_layer[3:5], 'big')
    per_recv = 1000
    data = b''
    while read_bytes > 0:
        data += conn.recv(min(per_recv, read_bytes))
        read_bytes = required_bytes - len(data)

    assert len(data) == required_bytes, 'Wrong size: expected {}, got {}'.format(required_bytes, len(data))
    return record_layer, data
