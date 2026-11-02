"""Network and timing for the keelbook engine inside the browser (Pyodide, in a Web Worker).

The engine uses urllib.request.urlopen and time.sleep. A browser has no sockets, so requests go
through the browser itself (synchronous XMLHttpRequest, allowed in a worker), which only reaches
services that allow it (OSV and NVD do). This must run before keelbook is imported: the NVD
client keeps a reference to time.sleep from import time.
"""

import concurrent.futures
import io
import time
import urllib.error
import urllib.request
from email.message import Message

import js  # the browser

# Headers the browser sets itself and refuses from scripts.
_BROWSER_HEADERS = {"user-agent", "host", "content-length", "connection", "accept-encoding", "origin", "referer"}


class _Response(io.BytesIO):
    def __init__(self, body: bytes, status: int, url: str, headers: Message):
        super().__init__(body)
        self.status = self.code = status
        self.url = url
        self.headers = headers

    def getcode(self):
        return self.status

    def geturl(self):
        return self.url

    def info(self):
        return self.headers


def _headers(raw: str) -> Message:
    message = Message()
    for line in (raw or "").splitlines():
        name, _, value = line.partition(":")
        if name.strip():
            message[name.strip()] = value.strip()
    return message


def urlopen(request, data=None, timeout=None, **_ignored):
    if isinstance(request, str):
        request = urllib.request.Request(request, data=data)
    url, method, body = request.full_url, request.get_method(), request.data
    xhr = js.XMLHttpRequest.new()
    xhr.open(method, url, False)
    xhr.responseType = "arraybuffer"
    for name, value in request.header_items():
        if name.lower() not in _BROWSER_HEADERS:
            xhr.setRequestHeader(name, value)
    try:
        xhr.send(body.decode("utf-8") if body else None)
    except Exception as exc:  # the browser refused (network down, blocked by the other site)
        raise urllib.error.URLError(f"network error ({exc})") from None
    if xhr.status == 0:
        raise urllib.error.URLError("no answer (offline, or the service does not allow browser requests)")
    raw = bytes(js.Uint8Array.new(xhr.response).to_py()) if xhr.response else b""
    headers = _headers(xhr.getAllResponseHeaders())
    if xhr.status >= 400:
        raise urllib.error.HTTPError(url, xhr.status, xhr.statusText, headers, io.BytesIO(raw))
    return _Response(raw, xhr.status, url, headers)


def _sleep(seconds: float) -> None:
    """Wait in the worker (the page stays responsive). Used for NVD's rate limit and retries."""
    end = time.monotonic() + max(0.0, seconds)
    while time.monotonic() < end:
        pass


class SerialExecutor:
    """Stands in for ThreadPoolExecutor: browsers have no threads, so tasks run one after another."""

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def submit(self, fn, *args, **kwargs):
        future = concurrent.futures.Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except BaseException as exc:  # handed to the caller through the future, as with threads
            future.set_exception(exc)
        return future

    def map(self, fn, *iterables, **kwargs):
        return [fn(*args) for args in zip(*iterables)]

    def shutdown(self, *args, **kwargs):
        pass


urllib.request.urlopen = urlopen
time.sleep = _sleep
concurrent.futures.ThreadPoolExecutor = SerialExecutor
