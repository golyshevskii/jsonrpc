from collections import deque
from datetime import datetime


class Connection:
    _connection = (None, None)
    _timeout = None
    _timeout_state = deque(maxlen=2)

    def make_connection(self, host):
        self._timeout_state.append(self._timeout)
        if host == self._connection[0]:
            if len(set(self._timeout_state)) <= 1:
                self.reset_timeout()
                return self._connection[1]

        self._connection = host, f'connection {host} -> {self._timeout}'
        self.reset_timeout()
        return self._connection[1]

    def set_timeout(self, timeout):
        try:
            self._timeout = float(timeout)
        except (ValueError, TypeError, Exception) as ex:
            self._timeout = None
            print(f'TransportMixIn > set_timeout: ERROR -> {datetime.now()}\n{ex.__class__.__name__}:\n{ex}')
            # raise Exception('Incorrect timeout value. Should be a number.')

    def reset_timeout(self):
        self._timeout = None


tests = (
    ('http_1', None),
    ('http_1', 60),
    ('http_1', '1O'),
    ('http_1', None),
    ('http_1', 30),
    ('http_1', 20),
    ('http_2', 100),
    ('http_2', None),
    ('http_2', None),
    ('http_2', 30)
)

conn = Connection()
for test in tests:
    host, timeout = test[0], test[1]
    if timeout:
        conn.set_timeout(timeout)
    print(f'TEST ({host}, {timeout}) -> {datetime.now()}')
    print(f'response > {conn.make_connection(host)}\nattributes > {conn.__dict__}')
