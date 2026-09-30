"""
Feature L2.9 - a robust, retrying HTTP-Range-based file-like reader for
remote ZIP archives, used to read the official CSE-CIC-IDS2018 pcap.zip's
central directory and extract individual small/medium entries WITHOUT
downloading the full ~52 GB archive.

Chunks each read into bounded-size HTTP Range requests (default 4 MiB)
with retries, since this environment's network has shown intermittent
mid-transfer resets on large single transfers (see this project's prior
results/external_dataset_preparation/download_manifest.json for the same
characteristic on a different large download).
"""

import io
import time
import urllib.error
import urllib.request

DEFAULT_CHUNK = 4 * 1024 * 1024  # 4 MiB per HTTP request


class RangeFile(io.RawIOBase):
    def __init__(self, url: str, chunk_size: int = DEFAULT_CHUNK, max_retries: int = 5):
        self.url = url
        self.chunk_size = chunk_size
        self.max_retries = max_retries
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=20) as resp:
            self.length = int(resp.headers["Content-Length"])
        self.pos = 0
        self.bytes_fetched = 0
        self.requests_made = 0

    def seekable(self):
        return True

    def seek(self, offset, whence=0):
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        elif whence == 2:
            self.pos = self.length + offset
        return self.pos

    def tell(self):
        return self.pos

    def readable(self):
        return True

    def _fetch_range(self, start: int, end: int) -> bytes:
        last_err = None
        for attempt in range(1, self.max_retries + 1):
            try:
                req = urllib.request.Request(self.url, headers={"Range": f"bytes={start}-{end}"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = resp.read()
                self.requests_made += 1
                return data
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
                last_err = e
                time.sleep(min(2 ** attempt, 10))
        raise RuntimeError(f"Failed to fetch bytes {start}-{end} after {self.max_retries} retries: {last_err}")

    def read(self, size=-1):
        target_end = (self.length - 1) if (size is None or size < 0) else (min(self.pos + size, self.length) - 1)
        if target_end < self.pos:
            return b""
        out = bytearray()
        cur = self.pos
        while cur <= target_end:
            chunk_end = min(cur + self.chunk_size - 1, target_end)
            data = self._fetch_range(cur, chunk_end)
            out += data
            self.bytes_fetched += len(data)
            cur += len(data)
            if len(data) == 0:
                break
        self.pos = cur
        return bytes(out)
