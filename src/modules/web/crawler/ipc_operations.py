import base64
import pickle

RECV_BUFFER_SIZE = 4096


def send_object(connection, obj):
    """
    Send the given Python object over the given connection.
    """

    # pickle the object, encode it in base64 and send it
    obj_enc = base64.b64encode(pickle.dumps(obj)).decode()
    msg = ("%s\n" % obj_enc).encode()
    connection.sendall(msg)


def receive_object(connection, buffer_size=RECV_BUFFER_SIZE):
    """
    Receive an object over the given connection.
    :return: None if the connection is closed, an object otherwise
    """

    # receive a base64 string, decode and unpickle it to get the object
    full_data = ""
    while True:
        data = connection.recv(buffer_size)
        data = data.decode()
        if not data:
            return None
        if "\n" in data:
            data, _ = data.split("\n")
            full_data += data
            break
        full_data += data

    if full_data:
        return pickle.loads(base64.b64decode(full_data))
    return None
