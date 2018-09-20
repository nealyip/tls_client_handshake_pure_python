def prepend_length(data, *, len_byte_size):
    return len(data).to_bytes(len_byte_size, 'big') + data


def pack(header_type, tls_version, data, *, len_byte_size):
    return header_type + prepend_length(tls_version + data, len_byte_size=len_byte_size)


def record(content_type, tls_version, data):
    return content_type + tls_version + prepend_length(data, len_byte_size=2)
