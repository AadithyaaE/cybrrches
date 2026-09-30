"""
Feature L2.9 - streams a single ZIP entry's DECOMPRESSED bytes from the
remote pcap.zip archive (via zipfile's own streaming zf.open(), backed by
RangeFile) and stops as soon as a packet timestamp crosses a given UTC
cutoff, writing only the packets read so far to a local pcap file. This
avoids downloading the full entry (potentially 100+ MB) when only an
early portion is needed to overlap the training CSV's covered window.
"""

import struct
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from data.pcap_ground_truth_correlation.range_zip_fetch import RangeFile  # noqa: E402

PCAP_GLOBAL_HEADER_LEN = 24
PCAP_RECORD_HEADER_LEN = 16


def bounded_extract(zip_url: str, entry_name: str, cutoff_epoch_s: int, out_path: str, max_packets: int = 5_000_000):
    rf = RangeFile(zip_url)
    zf = zipfile.ZipFile(rf)

    with zf.open(entry_name) as fh:
        global_header = fh.read(PCAP_GLOBAL_HEADER_LEN)
        magic = global_header[0:4]
        little = magic == b"\xd4\xc3\xb2\xa1"
        endian = "<" if little else ">"

        out = bytearray()
        out += global_header

        n_packets = 0
        last_ts = None
        while n_packets < max_packets:
            rec_header = fh.read(PCAP_RECORD_HEADER_LEN)
            if len(rec_header) < PCAP_RECORD_HEADER_LEN:
                break  # end of stream
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", rec_header)
            if ts_sec > cutoff_epoch_s:
                break
            payload = fh.read(incl_len)
            if len(payload) < incl_len:
                break
            out += rec_header
            out += payload
            n_packets += 1
            last_ts = ts_sec

    Path(out_path).write_bytes(bytes(out))
    return {
        "packets_written": n_packets,
        "last_ts_epoch": last_ts,
        "network_bytes_fetched": rf.bytes_fetched,
        "http_requests_made": rf.requests_made,
        "out_path": out_path,
        "out_size_bytes": len(out),
    }


if __name__ == "__main__":
    import json
    zip_url = sys.argv[1]
    entry_name = sys.argv[2]
    cutoff = int(sys.argv[3])
    out_path = sys.argv[4]
    result = bounded_extract(zip_url, entry_name, cutoff, out_path)
    print(json.dumps(result, indent=2))
