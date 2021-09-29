"""A docker-based mininet host"""

import json
import operator
import os
import pty
import select
from subprocess import PIPE, STDOUT
from functools import reduce

# pylint: disable=import-error
from mininet.log import error, debug
from mininet.node import Host
from mininet.util import quietRun, errRun

from clib.mininet_test_util import DEVNULL

DEFAULT_NETWORK = 'none'
DEFAULT_PREFIX = 'mininet'
STARTUP_TIMEOUT_MS = 20000

# pylint: disable=too-many-instance-attributes


class DockerHost(Host):
    """Mininet host that encapsulates execution in a docker container"""

    master = None
    shell = None
    slave = None
    name = None
    inNamespace = None
    pollOut = None
    stdout = None
    execed = None
    lastCmd = None  # pylint: disable=invalid-name
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
    container = None
    pollIn = None
    active_log = None
    ps1 = chr(127)

    # pylint: disable=too-many-arguments
    def __init__(self, name, image=None, tmpdir=None, prefix=None, env_vars=None, vol_maps=None,
                 startup_timeout_ms=STARTUP_TIMEOUT_MS, network=None, **kwargs):
        self.image = image
        self.tmpdir = tmpdir
        self.prefix = prefix
        if env_vars is None:
            env_vars = []
        self.env_vars = env_vars
        if vol_maps is None:
            vol_maps = []
        self.vol_maps = vol_maps
        self.network = network
        self.startup_timeout_ms = startup_timeout_ms
        self.name = name
        self.pullImage()
        Host.__init__(self, name, **kwargs)

    def pullImage(self):  # pylint: disable=invalid-name
        "Pull docker image if necessary"
        if self.image not in quietRun('docker images'):
            error(f'{self.name}: docker image', self.image,
                  'not available locally - pulling\n')
            _out, err, code = errRun('docker', 'pull', self.image)
            if err or code:
                error('docker pull failed with error', code, err, '\n')

    # pylint: disable=invalid-name
    def startShell(self, mnopts=None):
        """Start a shell process for running commands."""
        if self.shell:
            error('shell is already running')
            return

        assert mnopts is None, 'mnopts not supported for DockerHost'

        self.container = f'{self.prefix}-{self.name}'

        debug(f'Starting container {self.container} with image "{self.image}".')

        self.kill(purge=True)

        container_tmp_dir = os.path.join(os.path.abspath(self.tmpdir), 'tmp')
        tmp_volume = container_tmp_dir + ':/tmp'

        base_cmd = ["docker", "run", "-ti", "--privileged", "--entrypoint", "env",
                    "-h", self.name, "--name", self.container]
        opt_args = [f'--net={self.network}']
        env_vars = self.env_vars + ["TERM=dumb", f"PS1={self.ps1}"]
        env_args = reduce(operator.add, (['--env', var] for var in env_vars), [])
        vol_args = reduce(operator.add, (['-v', var] for var in self.vol_maps), ['-v', tmp_volume])
        image_args = [self.image, "bash", "--norc", "-is", "mininet:" + self.name]
        cmd = base_cmd + opt_args + env_args + vol_args + image_args
        self.master, self.slave = pty.openpty()
        debug(f'docker command {" ".join(cmd)}, fd {self.master}, fd {self.slave}')
        try:
            self.shell = self._popen(cmd, stdin=self.slave, stdout=self.slave, stderr=self.slave)
            self.stdin = os.fdopen(self.master, 'r')
            self.stdout = self.stdin
            self.pollOut = select.poll()  # pylint: disable=invalid-name
            self.pollOut.register(self.stdout)  # pylint: disable=no-member
            self.outToNode[self.stdout.fileno()] = self  # pylint: disable=no-member
            self.pollIn = select.poll()  # pylint: disable=invalid-name
            self.pollIn.register(self.stdout, select.POLLIN)  # pylint: disable=no-member
            self.inToNode[self.stdin.fileno()] = self  # pylint: disable=no-member
            self.execed = False
            self.lastCmd = None  # pylint: disable=invalid-name
            self.lastPid = None  # pylint: disable=invalid-name
            self.readbuf = ''
            self.waiting = True
            data = ''
            while True:
                data = self.read(1)
                if data[-1] == self.ps1:
                    break
            self.readbuf = ''
            self.waiting = False
        except Exception:
            error(f'docker cmd: {" ".join(cmd)}')
            if self.shell.returncode:
                error(f'returncode: {self.shell.returncode}')
            if self.shell:
                self.shell.poll()
            raise

        self.pid = self.inspect_pid()
        debug(f"Container {self.container} created pid {self.pid}/{self.shell.pid}.")

        self.cmd('unset HISTFILE; stty -echo; set +m')  # pylint: disable=no-member

    def kill(self, purge=False):
        """Kill a container."""
        debug(f'killing container {self.container}.')
        if purge:
            kill_cmd = ["docker", "rm", "-f", self.container]
        else:
            kill_cmd = ["docker", "kill", self.container]
        kill_pipe = None
        try:
            kill_pipe = self._popen(kill_cmd, stdin=DEVNULL, stdout=PIPE, stderr=STDOUT)
            kill_pipe.stdout.readlines()
            kill_pipe.stdout.close()
        except Exception:
            if kill_pipe:
                kill_pipe.poll()
            raise

    def inspect_pid(self):
        """Return container PID."""
        pid_pipe = None
        try:
            pid_cmd = ["docker", "inspect", "--format={{ .State.Pid }}", self.container]
            pid_pipe = self._popen(pid_cmd, stdin=DEVNULL, stdout=PIPE, stderr=STDOUT)
            ps_out = pid_pipe.stdout.readlines()
            pid_pipe.stdout.close()
            return int(ps_out[0])
        except Exception:
            if pid_pipe is not None:
                pid_pipe.poll()
            raise

    def open_log(self):
        """Open a log file for writing and return it."""
        # pylint: disable=consider-using-with
        return open(os.path.join(self.tmpdir, 'activate.log'), 'w')

    def activate(self):
        """Activate a container and return STDOUT to it."""
        assert not self.active_pipe, f'container {self.container} already activated'
        debug(f'activating container {self.container}.')
        inspect_cmd = ["docker", "inspect", "--format={{json .Config}}", self.image]
        inspect_pipe = None
        try:
            inspect_pipe = self._popen(inspect_cmd, stdin=DEVNULL, stdout=PIPE, stderr=STDOUT)
            config_json = inspect_pipe.stdout.readlines()
            inspect_pipe.stdout.close()
            assert len(config_json) == 1, f"Expected 1 config line, found {len(config_json)}"
            config = json.loads(config_json[0].decode())
            entryconfig = config['Entrypoint']
            entrypoint = entryconfig if entryconfig else ['/usr/bin/env']
            cmd = config['Cmd'] if 'Cmd' in config else []
            docker_cmd = entrypoint + (cmd if cmd else [])
            debug(f'logging to activate.log for {docker_cmd}')
            stdout = self.open_log()
            self.active_log = stdout
        except Exception:
            if inspect_pipe:
                inspect_pipe.poll()
            raise
        self.active_pipe_returncode = None
        self.active_pipe = self.popen(docker_cmd, stdin=DEVNULL, stdout=stdout, stderr=STDOUT)
        pipe_out = self.active_pipe.stdout
        out_fd = pipe_out.fileno() if pipe_out else None
        debug(f'Active_pipe container {self.container} pid {self.active_pipe.pid} fd {out_fd}')
        return self.active_pipe

    def wait(self):
        """Wait for an activated container to terminate."""
        try:
            if self.active_pipe_returncode is not None:
                return self.active_pipe_returncode
            debug(f'Waiting for container {self.container}.')
            assert self.active_pipe, "container not activated"
            self.active_pipe.communicate()
            self.active_pipe.returncode = self.active_pipe.wait()
            self.terminate()
            return self.active_pipe_returncode
        except Exception as err:
            error(f'Exception waiting for {self.container}: {err}')
            self.terminate()
            raise

    def read(self, size=1024):
        """Read from an activated container."""
        poll_results = self.pollIn.poll(self.startup_timeout_ms)
        data_ready = poll_results and (poll_results[0][1] & select.POLLIN)
        assert data_ready, (
            'Timeout waiting for read data on %d after %ds' %
            (self.stdout.fileno(), self.startup_timeout_ms / 1e3))
        return Host.read(self, size)

    def terminate(self):
        """Override Mininet terminate() to partially avoid pty leak."""
        debug(f'Terminating container {self.container}, shell {self.shell}, pipe {self.active_pipe}')
        if self.slave:
            os.close(self.slave)
            self.slave = None
        if self.shell is not None:
            self.stdin.close()
            self.stdin = None
            self.master = None
            if self.shell.returncode is None:
                self.shell.kill()
                self.shell.poll()
            self.kill()
            self.shell = None
        if self.active_pipe:
            if self.active_pipe.stdout:
                self.active_pipe.stdout.close()
            if self.active_pipe.returncode is None:
                self.active_pipe.kill()
                self.active_pipe.poll()
            self.active_pipe_returncode = self.active_pipe.returncode
            self.active_pipe = None
            if self.active_log:
                self.active_log.close()
                self.active_log = None
        self.cleanup()  # pylint: disable=no-member
        return self.active_pipe_returncode

    def popen(self, *args, **kwargs):
        """Return a Popen() object in node's namespace
           args: Popen() args, single list, or string
           kwargs: Popen() keyword args"""
        # -t is necessary to prevent docker from buffering output. It might cause
        # problems with some commands like shells that then assume they can output
        # all sorts of crazy control characters b/c it's a terminal.
        mncmd = ['docker', 'exec', '--env', 'TERM=dumb', '-t', self.container]
        pipe = Host.popen(self, mncmd=mncmd, *args, **kwargs)
        if pipe:
            debug(f'docker pid {pipe.pid}: {mncmd} {args} {kwargs}')
        return pipe

    def _popen(self, cmd, **params):
        # Docker is different than mininet in that it doesn't handle signals like
        # a normal interactive terminal would. So, put it in a separate process group
        # so it doesn't receive stray SIGINTs, rather relying on the message sent
        # from the owning process through the pty.
        if 'preexec_fn' not in params:
            params['preexec_fn'] = os.setpgrp
        pipe = super()._popen(cmd, **params)
        if pipe:
            stdout = pipe.stdout
            out_fd = pipe.stdout.fileno() if stdout else None
            debug(f'docker pid {pipe.pid}: {cmd}, fd {out_fd}')
        return pipe


def make_docker_host(image, prefix=DEFAULT_PREFIX, network=DEFAULT_NETWORK,
                     startup_timeout_ms=None):
    """Utility function to create a docker-host class that can be passed to mininet"""

    class _ImageHost(DockerHost):
        """Internal class that represents a docker image host"""
        def __init__(self, *args, **kwargs):
            host_name = args[0]
            kwargs['image'] = image
            assert kwargs['tmpdir'], 'tmpdir required for docker host'
            kwargs['tmpdir'] = os.path.join(kwargs['tmpdir'], host_name)
            kwargs['prefix'] = prefix
            kwargs['network'] = network
            if startup_timeout_ms:
                kwargs['startup_timeout_ms'] = startup_timeout_ms
            elif 'DOCKER_STARTUP_TIMEOUT_MS' in os.environ:
                env_val = os.environ['DOCKER_STARTUP_TIMEOUT_MS']
                if env_val:
                    kwargs['startup_timeout_ms'] = int(env_val)
            super().__init__(*args, **kwargs)

    return _ImageHost
