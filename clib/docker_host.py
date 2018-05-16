"""A docker-based mininet host"""

import json
import operator
import os
import pty
import re
import select
import time

# pylint: disable=import-error
from mininet.log import error, debug
from mininet.node import Host
from subprocess import PIPE, STDOUT

from mininet_test_util import DEVNULL

def MakeDockerHost(image, prefix='mininet', startup_timeout_ms=None):
    class ImageHost(DockerHost):
        def __init__( self, *args, **kwargs ):
            host_name = args[0]
            kwargs['image'] = image
            assert kwargs['tmpdir'], 'tmpdir required for docker host'
            kwargs['tmpdir'] = os.path.join(kwargs['tmpdir'], host_name)
            kwargs['prefix'] = prefix
            if startup_timeout_ms:
                kwargs['startup_timeout_ms'] = startup_timeout_ms
            elif 'DOCKER_STARTUP_TIMEOUT_MS' in os.environ:
                env_val = os.environ['DOCKER_STARTUP_TIMEOUT_MS']
                if env_val:
                    kwargs['startup_timeout_ms'] = int(env_val)
            DockerHost.__init__(self, *args, **kwargs )
    return ImageHost


class DockerHost(Host):

    STARTUP_TIMEOUT_MS = 20000

    master = None
    shell = None
    slave = None
    name = None
    inNamespace = None
    pollOut = None
    stdout = None
    execed = None
    lastCmd = None # pylint: disable=invalid-name
    readbuf = None
    lastPid = None
    pid = None
    waiting = None
    stdin = None
    active_pipe = None
    active_pipe_returncode = None
    image = None
    tmpdir = None
    env_vars = None
    vol_maps = None
    prefix = None
    startup_timeout_ms = None


    def __init__(self, name, image=None, tmpdir=None, prefix=None, env_vars=[],
            vol_maps=[], startup_timeout_ms=STARTUP_TIMEOUT_MS, **kwargs ):
        self.image = image
        self.tmpdir = tmpdir
        self.prefix = prefix
        self.env_vars = env_vars
        self.vol_maps = vol_maps
        self.startup_timeout_ms = startup_timeout_ms
        Host.__init__( self, name, **kwargs )

    def startShell( self ):
        "Start a shell process for running commands"
        if self.shell:
            error( "%s: shell is already running" )
            return

        self.container = '%s-%s' % (self.prefix, self.name)

        debug('Starting container %s with image "%s".' % (self.container, self.image))

        self.kill(purge=True)

        container_tmp_dir = os.path.join(os.path.abspath(self.tmpdir), 'tmp')
        tmp_volume = container_tmp_dir + ':/tmp'

        base_cmd = [ "docker", "run", "-ti", "--privileged", "--entrypoint", "env",
                     "--net=none", "-h", self.name, "--name", self.container ]
        env_args = reduce(operator.add, ([ '--env', var ] for var in self.env_vars), [])
        vol_args = reduce(operator.add, ([ '-v', var ] for var in self.vol_maps), [ '-v', tmp_volume ])
        image_args = [ self.image, "TERM=dumb", "PS1=" + chr(127), "bash", "--norc",
            "-is", "mininet:" + self.name ]
        cmd = base_cmd + env_args + vol_args + image_args
        self.master, self.slave = pty.openpty()
        debug('docker command "%s", fd %d, fd %d' % (' '.join(cmd), self.master, self.slave))
        try:
            self.shell = self._popen(cmd, stdin=self.slave, stdout=self.slave, stderr=self.slave)
            self.stdin = os.fdopen(self.master, 'rw')
            self.stdout = self.stdin
            self.pollOut = select.poll() # pylint: disable=invalid-name
            self.pollOut.register(self.stdout) # pylint: disable=no-member
            self.outToNode[self.stdout.fileno()] = self # pylint: disable=no-member
            self.pollIn = select.poll() # pylint: disable=invalid-name
            self.pollIn.register(self.stdout, select.POLLIN) # pylint: disable=no-member
            self.inToNode[self.stdin.fileno()] = self # pylint: disable=no-member
            self.execed = False
            self.lastCmd = None # pylint: disable=invalid-name
            self.lastPid = None # pylint: disable=invalid-name
            self.readbuf = ''
            self.waiting = True
            data = ''
            while True:
                data = self.read()
                if data[-1] == chr(127):
                    break
            self.readbuf = ''
            self.waiting = False
        except:
            if self.shell:
                self.shell.poll()
            raise

        self.pid = self.inspect_pid()
        debug("Container %s created pid %s/%s." % (self.container, self.pid, self.shell.pid))

        self.cmd('unset HISTFILE; stty -echo; set +m') # pylint: disable=no-member

    def kill(self, purge=False):
        debug('killing container %s.' % self.container)
        if purge:
            kill_cmd = [ "docker", "rm", "-f", self.container ]
        else:
            kill_cmd = [ "docker", "kill", self.container ]
        try:
            kill_pipe = self._popen( kill_cmd, stdin=DEVNULL, stdout=PIPE, stderr=STDOUT)
            kill_pipe.stdout.readlines()
            kill_pipe.stdout.close()
        except:
            if kill_pipe:
                kill_pipe.poll()
            raise

    def inspect_pid(self):
        try:
            pid_cmd = ["docker","inspect","--format={{ .State.Pid }}", self.container]
            pid_pipe = self._popen( pid_cmd, stdin=DEVNULL, stdout=PIPE, stderr=STDOUT)
            ps_out = pid_pipe.stdout.readlines()
            pid_pipe.stdout.close()
            return int(ps_out[0])
        except:
            if pid_pipe:
                pid_pipe.poll()
            raise

    def open_log(self, log_name='activate.log'):
        return open(os.path.join(self.tmpdir, log_name), 'w')

    def activate(self, log_name='activate.log'):
        assert not self.active_pipe, 'container %s already activated' % self.container
        debug('activating container %s.' % self.container)
        inspect_cmd = ["docker", "inspect", "--format={{json .Config}}", self.image]
        try:
            inspect_pipe = self._popen(inspect_cmd, stdin=DEVNULL, stdout=PIPE, stderr=STDOUT)
            config_json = inspect_pipe.stdout.readlines()
            inspect_pipe.stdout.close()
            assert len(config_json) == 1, "Expected 1 config line, found %s" % len(config_json)
            config = json.loads(config_json[0])
            entryconfig = config['Entrypoint']
            entrypoint = entryconfig if entryconfig else ['/usr/bin/env']
            cmd = config['Cmd'] if 'Cmd' in config else []
            docker_cmd = entrypoint + (cmd if cmd else [])
            debug('logging to %s for %s' % (log_name, docker_cmd))
            if log_name:
                stdout = self.open_log(log_name)
                self.active_log = stdout
            else:
                stdout = PIPE
                self.active_log = None
        except:
            if inspect_pipe:
                inspect_pipe.poll()
            raise
        self.active_pipe_returncode = None
        self.active_pipe = self.popen(docker_cmd, stdin=DEVNULL, stdout=stdout, stderr=STDOUT)
        pipe_out = self.active_pipe.stdout
        out_fd = pipe_out.fileno() if pipe_out else None
        debug('Active_pipe container %s pid %s fd %s' %
              (self.container, self.active_pipe.pid, out_fd))
        return self.active_pipe

    def wait(self):
        try:
            if self.active_pipe_returncode != None:
                return self.active_pipe_returncode
            debug('Waiting for container %s.' % self.container)
            assert self.active_pipe, "container not activated"
            self.active_pipe.communicate()
            self.active_pipe.returncode = self.active_pipe.wait()
            self.terminate()
            return self.active_pipe_returncode
        except Exception as e:
            error('Exception waiting for %s: %s' % (self.container, e))
            self.terminate()
            raise

    def read( self, maxbytes=1024 ):
        poll_results = self.pollIn.poll(self.startup_timeout_ms)
        data_ready = poll_results and (poll_results[0][1] & select.POLLIN)
        assert data_ready, ('Timeout waiting for read data on %d after %ds' %
            (self.stdout.fileno(), self.startup_timeout_ms / 1000))
        return Host.read(self, maxbytes)

    def terminate(self):
        """Override Mininet terminate() to partially avoid pty leak."""
        debug('Terminating container %s, shell %s, pipe %s' % (self.container, self.shell, self.active_pipe))
        if self.slave:
            os.close(self.slave)
            self.slave = None
        if self.shell is not None:
            self.stdin.close()
            self.stdin = None
            self.master = None
            if self.shell.returncode == None:
                self.shell.kill()
                self.shell.poll()
            self.kill()
            self.shell = None
        if self.active_pipe:
            if self.active_pipe.stdout:
                self.active_pipe.stdout.close()
            if self.active_pipe.returncode == None:
                self.active_pipe.kill()
                self.active_pipe.poll()
            self.active_pipe_returncode = self.active_pipe.returncode
            self.active_pipe = None
            if self.active_log:
                self.active_log.close()
                self.active_log = None
        self.cleanup() # pylint: disable=no-member
        return self.active_pipe_returncode

    def popen( self, *args, **kwargs ):
        """Return a Popen() object in node's namespace
           args: Popen() args, single list, or string
           kwargs: Popen() keyword args"""
        # -t is necessary to prevent docker from buffering output. It might cause
        # problems with some commands like shells that then assume they can output
        # all sorts of crazy control characters b/c it's a terminal.
        mncmd = [ 'docker', 'exec', '--env', 'TERM=dumb', '-t', self.container ]
        pipe = Host.popen( self, mncmd=mncmd, *args, **kwargs )
        if pipe:
            debug('docker pid %d: %s %s %s' % (pipe.pid, mncmd, args, kwargs))
        return pipe

    def _popen(self, cmd, **params):
        # Docker is different than mininet in that it doesn't handle signals like
        # a normal interactive terminal would. So, put it in a separate process group
        # so it doesn't receive stray SIGINTs, rather relying on the message sent
        # from the owning process through the pty.
        if not 'preexec_fn' in params:
            params['preexec_fn'] = os.setpgrp
        pipe = super(DockerHost, self)._popen(cmd, **params)
        if pipe:
            stdout = pipe.stdout
            out_fd = pipe.stdout.fileno() if stdout else None
            debug('docker pid %d: %s, fd %s' % (pipe.pid, cmd, out_fd))
        return pipe
