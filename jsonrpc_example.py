import logging
import socket
import httplib

from common.helpers import format_error
from collections import deque
from datetime import datetime

import jsonrpclib
import jsonrpclib.jsonclass
import xmlrpclib
import base64
import ssl


class RpcClient(object):
    def __init__(self, url, ver, user=None, password=None):
        self.user = user
        self.password = password
        self.url = url
        self.ver = ver
        jsonrpclib.config.version = ver
        self._rpc = None
        self._transport = None
        self.logger = logging.getLogger(u'RpcClient')
        self.errors = 0
        self.__child_connections = []
        self._private = False
        self.__is_closed = False

    def _renew_rpc(self):
        try:
            if self.url.startswith('https'):
                self._transport = jsonrpclib.jsonrpc.SafeTransport()
            else:
                self._transport = Transport()
            if self.user is not None and self.password is not None:
                self._transport.set_basic_auth(self.user, self.password)
            self._rpc = jsonrpclib.Server(self.url, transport=self._transport)
        except:
            self.logger.error(format_error())

    def rpc(self):
        if self._rpc is None:
            self._renew_rpc()
        return self._rpc

    @property
    def private(self):
        return self._private

    @private.setter
    def private(self, value):
        self._private = value

    def __getattr__(self, item):
        def make_call(*args, **kwargs):
            try:
                result = getattr(self.rpc(), item)(*args, **kwargs)
                self.errors = 0
                self._private = False
                return result
            except socket.error:
                self.errors += 1
                if not self._private:
                    self.logger.warning('Request: {}'.format(jsonrpclib.history.request))
                    self.logger.warning('Response: {}'.format(jsonrpclib.history.response))
                self._rpc = None
                self._private = False
                raise
            except:
                if not self._private:
                    self.logger.warning('Request: {}'.format(jsonrpclib.history.request))
                    self.logger.warning('Response: {}'.format(jsonrpclib.history.response))
                self._rpc = None
                self._private = False
                raise
        # clear old requests
        jsonrpclib.history.clear()
        return make_call

    def copy(self):
        self.clear_closed_children()
        new_conn = RpcClient(self.url, self.ver, user=self.user, password=self.password)
        self.__child_connections.append(new_conn)
        return new_conn

    def close(self):
        self.close_children()
        if self._rpc is not None:
            self._transport.close()
        self.__is_closed = True

    def close_children(self):
        for child in self.__child_connections:
            child.close()
        self.__child_connections = []

    def clear_closed_children(self):
        self.__child_connections = [c for c in self.__child_connections if not c.__is_closed]
    
    def _set_timeout(self, timeout):
        if self._rpc is None:
            self._renew_rpc()
        self._rpc._ServerProxy__transport.set_timeout(timeout)


class SafeRpcClient(RpcClient):
    def __init__(self, url, ver, user=None, password=None):
        super(SafeRpcClient, self).__init__(url, ver, user, password)
        self.__child_connections = []
        self.__is_closed = False

    def _renew_rpc(self):
        try:
            self._transport = SafeTransport()
            if self.user is not None and self.password is not None:
                self._transport.set_basic_auth(self.user, self.password)
            self._rpc = jsonrpclib.Server(self.url, transport=self._transport)
        except:
            self.logger.error(format_error())

    def copy(self):
        self.clear_closed_children()
        new_conn = SafeRpcClient(self.url, self.ver, user=self.user, password=self.password)
        self.__child_connections.append(new_conn)
        return new_conn


###############################################################################
# Patch default jsonrpclib transport so that we send proper error even if     #
# status != 200. Code copied from jsonrpclib.jsonrpc && xmlrpclib             #
###############################################################################


class TransportMixIn(object):
    """ Just extends the XMLRPC transport where necessary. """
    user_agent = jsonrpclib.config.user_agent
    # for Python 2.7 support
    _connection = (None, None)
    _extra_headers = []
    __auth = None
    _timeout = socket._GLOBAL_DEFAULT_TIMEOUT
    _timeout_state = deque(maxlen=2)

    def set_basic_auth(self, user, password):
        self.__auth = "000000" + base64.b64encode("%s:%s" % (user, password))

    def send_content(self, connection, request_body):
        if self.__auth != None:
            connection.putheader("Authorization", self.__auth)
        connection.putheader("Content-Type", 'application/json')
        connection.putheader("Content-Length", str(len(request_body)))
        connection.endheaders()
        if request_body:
            connection.send(request_body)

    def getparser(self):
        target = JSONTarget()
        return JSONParser(target), target

    def make_connection(self, host):
        # we can remove add_timeout_state method, because we using it ones
        # self.add_timeout_state(self._timeout)

        # we can remove the _connection tuple check, since it always returns True
        # if self._connection and host == self._connection[0]:
        #     if len(set(self._timeout_state)) <= 1:
        #         self.reset_timeout()
        #         return self._connection[1]
        #     self.close()

        self._timeout_state.append(self._timeout)
        if host == self._connection[0]:
            if len(set(self._timeout_state)) < 2:
                self.reset_timeout()
                return self._connection[1]
            self.close()

        chost, self._extra_headers, x509 = self.get_host_info(host)
        if self.__class__.__name__ == 'Transport':
            self._connection = host, httplib.HTTPConnection(chost, timeout=self._timeout)
        elif self.__class__.__name__ == 'SafeTransport':
            self._connection = host, httplib.HTTPSConnection(chost, None, context=self.context, timeout=self._timeout, **(x509 or {}))
        self.reset_timeout()
        return self._connection[1]

    def set_timeout(self, timeout):
        # if isinstance(timeout, Hashable):
        #     # incorrect representation of a number as a string can get here, for example: '1.OO1', '12,34'
        #     self._timeout = timeout
        # else:
        #     raise ValueError('Incorrect timeout value. Should be a number.')

        try:
            self._timeout = float(timeout)
        except (ValueError, TypeError, Exception) as ex:
            print(f'TransportMixIn > set_timeout: ERROR -> {datetime.now()}\n{ex.__class__.__name__}:\n{ex}')
            raise Exception('Incorrect timeout value. Should be a number.')

    def reset_timeout(self):
        self._timeout = socket._GLOBAL_DEFAULT_TIMEOUT


class JSONParser(object):
    def __init__(self, target):
        self.target = target

    def feed(self, data):
        self.target.feed(data)

    def close(self):
        pass


class JSONTarget(object):
    def __init__(self):
        self.data = []

    def feed(self, data):
        self.data.append(data)

    def close(self):
        return ''.join(self.data)


class Transport(TransportMixIn, xmlrpclib.Transport):
    def __init__(self):
        TransportMixIn.__init__(self)
        xmlrpclib.Transport.__init__(self)

    def single_request(self, host, handler, request_body, verbose=0):
        # issue XML-RPC request
        h = self.make_connection(host)
        if verbose:
            h.set_debuglevel(1)

        try:
            self.send_request(h, handler, request_body)
            self.send_host(h, host)
            self.send_user_agent(h)
            self.send_content(h, request_body)

            response = h.getresponse(buffering=True)
            if response.status == 200:
                self.verbose = verbose
                return self.parse_response(response)
        except xmlrpclib.Fault:
            raise
        except Exception:
            # All unexpected errors leave connection in
            # a strange state, so we clear it.
            self.close()
            raise

        # discard any response data and raise exception
        if (int(response.getheader("content-length", 0))):
            # response.read()
            # Main difference is here. We do not discard the message - it may contain error code
            self.verbose = verbose
            return self.parse_response(response)
        raise xmlrpclib.ProtocolError(
            host + handler,
            response.status, response.reason,
            response.msg,
        )


class SafeTransport(TransportMixIn, xmlrpclib.SafeTransport):
    def __init__(self, cafile=None):
        # ssl_context = ssl.create_default_context()
        # ssl_context.check_hostname = False
        # ssl_context.verify_mode = ssl.CERT_NONE

        if cafile is None:
            ssl_context = ssl._create_unverified_context()
        else:
            ssl_context = ssl.create_default_context()
            ssl_context.load_verify_locations(cafile=cafile)
        TransportMixIn.__init__(self)
        xmlrpclib.SafeTransport.__init__(self, context=ssl_context)
