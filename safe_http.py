"""HTTPS fetches for explicitly configured public destinations, with DNS pinning."""
from __future__ import annotations
import gzip
import http.client
import ipaddress
import json
import socket
import ssl
import urllib.parse


def validate_url(url):
    if not isinstance(url,str) or len(url)>3000 or any(ord(c)<33 for c in url):
        raise ValueError("Enter a valid HTTPS URL.")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Use an HTTPS URL without embedded credentials or a fragment.")
    if parsed.port not in (None,443):
        raise ValueError("Public connectors use HTTPS port 443.")
    host = parsed.hostname.encode("idna").decode().lower()
    if host in {"localhost","metadata.google.internal"} or host.endswith((".localhost",".local",".internal")):
        raise ValueError("Connector destinations must be public internet hosts.")
    return parsed,host


def public_addresses(host,resolver=socket.getaddrinfo):
    try:
        rows = resolver(host,443,type=socket.SOCK_STREAM)
    except OSError:
        raise ValueError("The connector hostname could not be resolved.") from None
    addresses = []
    for row in rows:
        address = row[4][0]
        ip = ipaddress.ip_address(address)
        if not ip.is_global or ip.is_multicast or ip.is_unspecified or (ip.version==6 and ip.ipv4_mapped and not ip.ipv4_mapped.is_global):
            raise ValueError("The connector resolved to a non-public address.")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError("The connector hostname has no public address.")
    return sorted(addresses,key=lambda a:ipaddress.ip_address(a).version)


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,address,timeout=15):
        super().__init__(host,443,timeout=timeout,context=ssl.create_default_context())
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address,443),self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock,server_hostname=self.host)
        except BaseException:
            sock.close();raise


def request(url,body=None,headers=None,max_bytes=8*1024*1024):
    parsed,host = validate_url(url)
    addresses = public_addresses(host)
    connection = PinnedHTTPS(host,addresses[0])
    target = urllib.parse.urlunsplit(("","",parsed.path or "/",parsed.query,""))
    supplied = {"User-Agent":"MasterMonk/3.2","Accept":"application/json",**(headers or {})}
    try:
        connection.request("POST" if body is not None else "GET",target,body=body,headers=supplied)
        response = connection.getresponse()
        if not 200<=response.status<300:
            raise ValueError(f"The configured destination returned HTTP {response.status}.")
        data = response.read(max_bytes+1)
        if len(data)>max_bytes:
            raise ValueError("The connector response exceeded its size limit.")
        if response.getheader("Content-Encoding","").lower()=="gzip":
            import io
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                data = stream.read(max_bytes+1)
            if len(data)>max_bytes:
                raise ValueError("The expanded connector response exceeded its size limit.")
        return data,dict(response.getheaders())
    except (OSError,http.client.HTTPException) as exc:
        raise ValueError("The configured destination could not complete the request: "+type(exc).__name__) from None
    finally:
        connection.close()


def get_json(url):
    data,_ = request(url)
    return json.loads(data.decode("utf-8-sig"),parse_constant=lambda _:(_ for _ in ()).throw(ValueError("Non-finite JSON number.")))
