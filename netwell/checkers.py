import os
import re
import socket
import ssl
import subprocess
import sys
from contextlib import contextmanager
from datetime import timedelta, datetime
from typing import NoReturn, Optional
from urllib.parse import urlparse

import dns.resolver
import requests
from dns.exception import DNSException
from requests import Response


class RuleFailedException(Exception):
    pass


class Output:

    def __init__(self) -> None:
        self.quiet = False
        self.line = ''
        self.line_error = False

    def info(self, text) -> None:
        if not self.quiet or self.line_error:
            sys.stdout.write(self.line)
            self.line = ''
            sys.stdout.write(text)
            sys.stdout.flush()
        else:
            self.line += text

    def error(self, text) -> None:
        self.line_error = True
        self.info(text)

    def eol(self) -> None:
        self.info('\n')
        self.line_error = False
        self.line = ''


output = Output()


def set_output(out: Output):
    global output
    output = out


class Result:

    def __init__(self) -> None:
        self.failures = 0
        self.checks = 0


result = Result()


class Outcome:

    def __init__(self) -> None:
        self.failed = False
        self.message = None

    def fail(self, message=None) -> NoReturn:
        self.message = message
        self.failed = True
        raise RuleFailedException()


@contextmanager
def rule(description) -> None:
    output.info(description + '... ')
    outcome = Outcome()
    try:
        result.checks += 1
        yield outcome
    except RuleFailedException:
        pass
    except:
        outcome.failed = True
    if outcome.failed:
        result.failures += 1
        if outcome.message:
            output.error('ERROR')
            output.eol()
            output.error('ERROR: ' + outcome.message)
        else:
            output.error('ERROR')
    else:
        output.info('OK')
    output.eol()


class Checker:
    pass


class URL(Checker):

    def __init__(self, url: str) -> None:
        self.url: str = url
        self.response: Optional[Response] = None

    def _fetch(self) -> Response:
        if not self.response:
            self.response = requests.get(self.url, timeout=5)
        return self.response

    def redirects_to(self, to_url) -> object:
        with rule(f'Checking that {self.url} redirects to {to_url}') as outcome:
            response = self._fetch()
            if to_url != response.url:
                outcome.fail(f'{response.url} encountered')
        return self

    def title_matches(self, pattern) -> object:
        with rule(f'Checking that {self.url} title matches "{pattern}"') as outcome:
            response = self._fetch()
            m = re.search(r'title>(?P<title>[^<]+)</ti', response.text)
            title = m.group('title').strip()
            if not re.search(pattern, title, re.I):
                outcome.fail(f'got "{title}"')
        return self

    def has_header(self, header, value=None) -> object:
        """
        Checks if the specified header is present. In case a value is
        provided, it is checked if the value matches.
        """
        description = f'Checking that {self.url} has header "{header}"'
        if value is not None:
            description += f': "{value}"'
        with rule(description) as outcome:
            response = self._fetch()
            if value is not None:
                actual_value = response.headers.get(header, '')
                if actual_value != value:
                    outcome.fail(f'got {actual_value}')
            else:
                if header not in response.headers:
                    outcome.fail('not found')
        return self

    def check_response(self, func) -> object:
        with rule(f'Checking that {self.url} passes {func.__name__}') as outcome:
            response = self._fetch()
            func(response, outcome)
        return self

    def _get_netloc_port(self) -> tuple:
        parts = urlparse(self.url)
        netloc, _, port = parts.netloc.partition(':')
        if not port:
            if parts.scheme.lower() == 'https':
                port = 443
            else:
                port = 80
        return netloc, port


class Port(Checker):
    """
    Check that port is open at a server

        Port('webcookies.org', 443)

    """

    def __init__(self, netloc: str, port: int) -> None:
        self.netloc: str = netloc
        self.port: int = port
        self.context: ssl.SSLContext = ssl.create_default_context()
        self.cert: dict = {}
        socket.setdefaulttimeout(5.0)

    @staticmethod
    def _date(d: str) -> Optional[datetime]:
        try:
            # try decoding locale representation first
            return datetime.strptime(d, '%c')
        except ValueError:
            try:
                # try 'Jan 30 23:00:15 2019 GMT' representation
                return datetime.strptime(d, '%b %d %H:%M:%S %Y %Z')
            except ValueError:
                return None

    def is_open(self) -> object:
        """
        Check that the given port is open at given host

            Port('webcookies.org', 443).is_open()

        This can be used to test various non-HTTP and non-TLS protocols

        """
        with rule(f'Checking that port is open at {self.netloc}:{self.port}') as outcome:
            try:
                with socket.create_connection((self.netloc, self.port)) as sock:
                    return self
            except OSError as e:
                outcome.fail(f'Connection failed: {e}')

    def ssl_valid_for(self, *, days: int) -> object:
        """
        Check that TLS server is operational at given host and port, and certificate is valid for given number of days

            Port('webcookies.org', 443).ssl_valid_for(days=10)

        """
        with rule(f'Checking that TLS at {self.netloc}:{self.port} is valid for at least {days} days') as outcome:

            try:
                with socket.create_connection((self.netloc, self.port)) as sock:
                    with self.context.wrap_socket(sock, server_hostname=self.netloc) as ssl_sock:
                        self.cert = ssl_sock.getpeercert()
            except ssl.SSLError as e:
                outcome.fail(f'TLS error: {e}')
            else:
                not_before = self._date(self.cert.get('notBefore'))
                not_after = self._date(self.cert.get('notAfter'))

                now = datetime.now()

                if not not_before or not not_after:
                    outcome.fail('Unable to determine SSL dates')

                if now < not_before:
                    outcome.fail('Not valid before {}'.format(
                        not_before))

                if now + timedelta(days=days) > not_after:
                    outcome.fail('Not valid after {}'.format(
                        not_after))

            return self


class DNS(Checker):
    """
    Perform various DNS-related sanity checks. Initialize the class with a list of hostnames:

        DNS('example.com', 'www.example.com')

    """

    def __init__(self, *netlocs) -> None:
        self.netlocs = netlocs
        self.resolver = dns.resolver.Resolver()

    def resolves(self, record: str = 'A'):
        """
        Check if the hostnames resolve to any DNS record of given type (default: A)

            DNS('example.com').resolves()
            DNS('example.com', 'AAAA').resolves()
        """
        for netloc in self.netlocs:
            self._resolves_to(netloc, None, record)

    def resolves_to(self, ip: str, record: str = 'A') -> None:
        """
        Check if the hostnames resolve to specified A record

            DNS('example.com').resolves_to('127.0.0.1')
        """
        for netloc in self.netlocs:
            self._resolves_to(netloc, ip, record)

    def _resolves_to(self, netloc, ip, record):
        with rule(f'Checking that {netloc} resolves to {ip}') as outcome:
            try:
                answer = self.resolver.query(netloc, record)
            except DNSException as e:
                outcome.fail(f'got {e}')
            else:
                if ip and ip not in [str(x) for x in answer]:
                    outcome.fail(f'got str(list(answer))')


class Path(Checker):

    def __init__(self, path):
        self.path = path

    def modified_within(self, **kwargs):
        after = datetime.now() - timedelta(**kwargs)
        with rule(
                'Checking that {path} was modified after {dt}'.format(
                    path=self.path,
                    dt=after)) as outcome:
            t = os.path.getmtime(self.path)
            dt = datetime.fromtimestamp(t)
            if dt < after:
                outcome.fail('Last modified at {}'.format(dt))

    def free_space(self, mb=None, gb=None):
        assert not mb or not gb
        if mb is not None:
            unit = 'MB'
            bytes_per_unit = 1024 ** 2
        else:
            unit = 'GB'
            bytes_per_unit = 1024 ** 3
        value = mb or gb
        with rule(
                'Checking that {path} has {value} {unit} free space'.format(
                    unit=unit,
                    path=self.path,
                    value=value)) as outcome:
            st = os.statvfs(self.path)
            free = (st.f_bavail * st.f_frsize)
            # total = (st.f_blocks * st.f_frsize)
            # used = (st.f_blocks - st.f_bfree) * st.f_frsize
            free /= bytes_per_unit
            if free < value:
                outcome.fail('Only {free:.1f} {unit} free'.format(
                    free=free,
                    unit=unit))


class Repo(Checker):

    def __init__(self, path):
        self.path = path

    def is_clean(self):
        with rule('Checking that repository {path} is clean'.format(
                path=self.path)) as outcome:
            if not os.path.exists(os.path.join(self.path, '.git')):
                outcome.fail('No repository present')
            if not self._run_exit_0([
                'git', 'diff', '--exit-code']):
                outcome.fail('Local unstaged changes found')
            if not self._run_exit_0([
                'git', 'diff', '--cached', '--exit-code']):
                outcome.fail('Uncommitted, staged changes found')
            if self._has_untracked():
                outcome.fail('Untracked files found')

    def _has_untracked(self):
        out = subprocess.check_output(
            ['git', 'ls-files', '--other', '--exclude-standard',
             '--directory', '--no-empty-directory'],
            cwd=self.path)
        return len(out) > 0

    def _run_exit_0(self, args):
        try:
            subprocess.check_output(args, cwd=self.path)
            ret = True
        except subprocess.CalledProcessError:
            ret = False
        return ret
