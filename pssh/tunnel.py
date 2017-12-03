from threading import Thread
import logging
from gevent import sleep, socket, select, Greenlet

from ssh2.error_codes import LIBSSH2_ERROR_EAGAIN

from .native.ssh2 import wait_select


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logging.basicConfig()


class Tunnel(object):

    def __init__(self, channel, listen_port=0):
        # Greenlet.__init__(self)
        self.channel = channel
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('127.0.0.1', listen_port))
        self.socket.listen(0)
        self.listen_port = listen_port
        self.listen_port = self.socket.getsockname()[1] \
                           if listen_port == 0 else listen_port
        logger.debug("Tunnel listening on 127.0.0.1:%s", self.listen_port)
        # self.start()
        # sleep(0)

    def run(self):
        logger.debug("Tunnel waiting for connection")
        self.forward_sock, self.forward_addr = self.socket.accept()
        logger.debug("Tunnel got connection")
        while True:
            select.select(
                (self.forward_sock,),
                (), ())
                # raise Exception("Channel write error %s", rc)
            # import ipdb; ipdb.set_trace()
            ####
            # import ipdb; ipdb.set_trace()
            # import ipdb; ipdb.set_trace()
            rlist, _, _ = select.select(
                (self.forward_sock,), (), (), timeout=0.1)
            if len(rlist) == 0:
                continue
            data = self.forward_sock.recv(1024)
            data_len = len(data)
            logger.debug("Writing data from forward socket to channel")
            # import ipdb; ipdb.set_trace()
            data_written = 0
            while data_written < data_len:
                rc = self.channel.write(data)
                if rc == LIBSSH2_ERROR_EAGAIN:
                    wait_select(self.channel.session, timeout=0.1)
                    continue
                elif rc < 0:
                    logger.error("Channel write error %s", rc)
                data_written += rc
                logger.debug("Wrote %s bytes to channel", rc)
            logger.debug("Total channel write size %s from %s received",
                         data_written, data_len)
            ##
            size, data = self.channel.read()
            if size == LIBSSH2_ERROR_EAGAIN:
                wait_select(self.channel.session, timeout=0.1)
                size, data = self.channel.read()
            while size > 0:
                self.forward_sock.sendall(data)
                logger.debug("Forwarded %s bytes from channel", size)
                size, data = self.channel.read()
            ###
            sleep(.1)
            
            # sleep(.1)
            # if self.channel.eof():
            #     logger.debug("Channel closed, tunnel exiting")
            #     self.forward_sock.close()
            #     self.socket.close()
            #     return
            # sleep(.1)
