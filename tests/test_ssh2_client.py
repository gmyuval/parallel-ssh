import unittest
import os
import logging
import time
import subprocess

from gevent import socket

from .base_ssh2_test import SSH2TestCase
from .embedded_server.openssh import OpenSSHServer
from pssh.ssh2_client import SSHClient, logger as ssh_logger
from pssh.tunnel import Tunnel
from ssh2.session import Session
from pssh.exceptions import AuthenticationException, ConnectionErrorException, \
    SessionError


ssh_logger.setLevel(logging.DEBUG)
logging.basicConfig()


class SSH2ClientTest(SSH2TestCase):

    def test_execute(self):
        channel, host, stdout, stderr, stdin = self.client.run_command(
            self.cmd)
        output = list(stdout)
        stderr = list(stderr)
        expected = [self.resp]
        exit_code = channel.get_exit_status()
        self.assertEqual(exit_code, 0)
        self.assertEqual(expected, output)

    def test_stderr(self):
        channel, host, stdout, stderr, stdin = self.client.run_command(
            'echo "me" >&2')
        self.client.wait_finished(channel)
        output = list(stdout)
        stderr = list(stderr)
        expected = ['me']
        self.assertListEqual(expected, stderr)
        self.assertTrue(len(output) == 0)

    def test_long_running_cmd(self):
        channel, host, stdout, stderr, stdin = self.client.run_command(
            'sleep 2; exit 2')
        self.client.wait_finished(channel)
        exit_code = channel.get_exit_status()
        self.assertEqual(exit_code, 2)

    def test_manual_auth(self):
        client = SSHClient(self.host, port=self.port,
                           pkey=self.user_key,
                           num_retries=1,
                           timeout=1)
        client.session.disconnect()
        del client.session
        del client.sock
        client.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client._connect()
        client._init()
        # Identity auth
        client.pkey = None
        client.session.disconnect()
        del client.session
        del client.sock
        client.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client._connect()
        client.session = Session()
        client.session.handshake(client.sock)
        self.assertRaises(AuthenticationException, client.auth)

    def test_handshake_fail(self):
        client = SSHClient(self.host, port=self.port,
                           pkey=self.user_key,
                           num_retries=1)
        client.session.disconnect()
        self.assertRaises(SessionError, client._init)

    def test_stdout_parsing(self):
        dir_list = os.listdir(os.path.expanduser('~'))
        channel, host, stdout, stderr, stdin = self.client.run_command(
            'ls -la')
        output = list(stdout)
        # Output of `ls` will have 'total', '.', and '..' in addition to dir
        # listing
        self.assertEqual(len(dir_list), len(output) - 3)

    def test_file_output_parsing(self):
        lines = int(subprocess.check_output(
            ['wc', '-l', 'pssh/native/_ssh2.c']).split()[0])
        dir_name = os.path.dirname(__file__)
        ssh2_file = os.sep.join((dir_name, '..', 'pssh', 'native', '_ssh2.c'))
        channel, host, stdout, stderr, stdin = self.client.run_command(
            'cat %s' % ssh2_file)
        output = list(stdout)
        self.assertEqual(lines, len(output))

    def test_identity_auth_failure(self):
        self.assertRaises(AuthenticationException,
                          SSHClient, self.host, port=self.port, num_retries=1,
                          allow_agent=False)

    def test_agent_auth_failure(self):
        self.assertRaises(AuthenticationException,
                          SSHClient, self.host, port=self.port, num_retries=1,
                          allow_agent=True)

    def test_password_auth_failure(self):
        self.assertRaises(AuthenticationException,
                          SSHClient, self.host, port=self.port, num_retries=1,
                          allow_agent=False,
                          password='blah blah blah')

    def test_retry_failure(self):
        self.assertRaises(ConnectionErrorException,
                          SSHClient, self.host, port=12345,
                          num_retries=2)

    def test_direct_tcpip(self):
        from ssh2.session import Session
        # from socket import socket as pysock
        from gevent import spawn, sleep, joinall, wait
        # self.client.session.set_blocking(1)
        # chan = client.session.direct_tcpip(self.host, 22)
        # chan = client.session.direct_tcpip(self.host, 1234)
        # client.session.set_blocking(0)
        t = Tunnel(self.client.session, self.host, 22, listen_port=2223)
        # t.start()
        # t.get()
        # t.run()
        tunnel = spawn(t.run)
        tunnel.start()
        tunnel.get()
        # sleep(.5)
        # t.daemon = True
        # t.start()
        # import ipdb; ipdb.set_trace()
        ####
        # sleep(.5)
        # client = SSHClient(self.host, port=t.listen_port,
        #                    num_retries=1,
        #                    pkey=self.user_key,
        #                    timeout=2)
        # # client.start()
        # joinall((tunnel,), raise_error=True)
        # import ipdb; ipdb.set_trace()
        # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # sock.connect((self.host, t.listen_port))
        # sleep(0)
        # session = Session()
        # sleep(.5)
        # session.handshake(sock)
        # client = spawn(SSHClient, self.host, port=t.listen_port,
        #                pkey=self.user_key,
        #                num_retries=1)
        # client.start()
        # wait()
        # import ipdb; ipdb.set_trace()
        # sleep(2)
        # joinall((tunnel, client))
        # client = SSHClient(self.host, port=t.listen_port,
        #                    pkey=self.user_key,
        #                    num_retries=1)
        
