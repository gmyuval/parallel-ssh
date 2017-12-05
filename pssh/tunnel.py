from threading import Thread
import logging

from gevent import sleep, socket, select, Greenlet, spawn, joinall

from ssh2.session import LIBSSH2_SESSION_BLOCK_INBOUND, \
    LIBSSH2_SESSION_BLOCK_OUTBOUND
from ssh2.error_codes import LIBSSH2_ERROR_EAGAIN
from pssh.native.ssh2 import wait_select


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logging.basicConfig()


class Tunnel(object):

    def __init__(self, session, host, port, listen_port=0):
        # Greenlet.__init__(self)
        self.session = session
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('127.0.0.1', listen_port))
        self.socket.listen(0)
        self.listen_port = listen_port
        self.listen_port = self.socket.getsockname()[1] \
                           if listen_port == 0 else listen_port
        logger.debug("Tunnel listening on 127.0.0.1:%s", self.listen_port)
        self.host = host
        self.port = port
        self.channel = None
        self.forward_sock = None

    def __del__(self):
        self.socket.close()

    def _read_forward_sock(self):
        while True:
            logger.debug("Waiting on forward socket read")
            data = self.forward_sock.recv(1024)
            data_len = len(data)
            if data_len == 0:
                logger.error("Client disconnected")
                return
            data_written = 0
            rc = self.channel.write(data)
            while rc > 0 and data_written < data_len:
                # if rc == LIBSSH2_ERROR_EAGAIN:
                #     logger.debug("Waiting on channel write")
                #     wait_select(self.channel.session, self.client_sock)
                #     continue
                if rc < 0:
                    logger.error("Channel write error %s", rc)
                    return
                data_written += rc
                logger.debug("Wrote %s bytes from forward socket to channel", rc)
                rc = self.channel.write(data[data_written:])
            logger.debug("Total channel write size %s from %s received",
                         data_written, data_len)

    def _read_channel(self):
        while True:
            size, data = self.channel.read()
            logger.debug("Read size %s from channel", size)
            while size == LIBSSH2_ERROR_EAGAIN or size > 0:
                if size == LIBSSH2_ERROR_EAGAIN:
                    logger.debug("Waiting on channel")
                    wait_select(self.channel.session)
                    size, data = self.channel.read()
                elif size < 0:
                    logger.error("Error reading from channel")
                    return
                while size > 0:
                    self.forward_sock.sendall(data)
                    logger.debug("Forwarded %s bytes from channel", size)
                    # select.select(
                    #     (), (self.forward_sock,), ())
                    size, data = self.channel.read()
                    logger.debug("Read %s from channel..", size)
            if self.channel.eof():
                logger.debug("Channel closed")
                return

    def run(self):
        while True:
            logger.debug("Tunnel waiting for connection")
            self.forward_sock, forward_addr = self.socket.accept()
            logger.debug("Client connected, forwarding %s:%s on"
                         " remote host to local %s",
                         self.host, self.port,
                         forward_addr)
            self.session.set_blocking(1)
            self.channel = self.session.direct_tcpip_ex(
                self.host, self.port, '127.0.0.1', forward_addr[1])
            if self.channel is None:
                self.forward_sock.close()
                self.socket.close()
                raise Exception("Could not establish channel to %s:%s",
                                self.host, self.port)
            self.session.set_blocking(0)
            source = spawn(self._read_forward_sock)
            dest = spawn(self._read_channel)
            joinall((source, dest))
            self.forward_sock.close()
