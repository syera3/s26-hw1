# Allowed Modules
import logging
import socket
import sys
import gzip 
import ssl
# End of Allowed Modules
# Adding any extra module will result into score of 0

def retrieve_url(url):
    """
    return bytes of the body of the document at url
    """

    def parse_url(u):
        u = u.strip()
        if u.startswith("http://"):
            scheme = "http"
            rest = u[7:]
            default_port = 80
        elif u.startswith("https://"):
            scheme = "https"
            rest = u[8:]
            default_port = 443
        else:
            return None

        slash = rest.find("/")
        if slash == -1:
            hostport = rest
            path = "/"
        else:
            hostport = rest[:slash]
            path = rest[slash:] or "/"

        if not hostport:
            return None

        if ":" in hostport:
            host, p = hostport.rsplit(":", 1)
            try:
                port = int(p)
            except ValueError:
                return None
        else:
            host = hostport
            port = default_port

        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            return None

        if not path.startswith("/"):
            path = "/" + path

        return scheme, host, port, path

    def connect(scheme, host, port):
        s = socket.create_connection((host, port), timeout=15)
        if scheme == "https":
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=host)
        return s

    def recv_until(s, marker):
        data = b""
        while marker not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    def read_exact(s, n):
        data = b""
        while len(data) < n:
            chunk = s.recv(min(4096, n - len(data)))
            if not chunk:
                break
            data += chunk
        return data

    def parse_headers(header_blob):
        try:
            text = header_blob.decode("iso-8859-1")
        except Exception:
            return None, {}

        lines = text.split("\r\n")
        if not lines or not lines[0].startswith("HTTP/"):
            return None, {}

        parts = lines[0].split(" ", 2)
        if len(parts) < 2:
            return None, {}

        try:
            status = int(parts[1])
        except ValueError:
            return None, {}

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status, headers

    def read_chunked(s, leftover):
        buf = leftover
        body = b""

        def get_line():
            nonlocal buf
            while b"\r\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    return None
                buf += chunk
            line, buf2 = buf.split(b"\r\n", 1)
            buf = buf2
            return line

        while True:
            line = get_line()
            if line is None:
                return None

            if b";" in line:
                line = line.split(b";", 1)[0]
            line = line.strip()
            if not line:
                continue

            try:
                size = int(line.decode("ascii"), 16)
            except Exception:
                return None

            if size == 0:
                return body

            while len(buf) < size + 2:
                chunk = s.recv(4096)
                if not chunk:
                    return None
                buf += chunk

            body += buf[:size]
            buf = buf[size + 2:]

    def read_body(s, headers, leftover):
        te = headers.get("transfer-encoding", "").lower()
        cl = headers.get("content-length", "")
        ce = headers.get("content-encoding", "").lower()

        if "chunked" in te:
            body = read_chunked(s, leftover)
            if body is None:
                return None
        elif cl:
            try:
                n = int(cl)
            except ValueError:
                return None
            body = leftover
            if len(body) < n:
                body += read_exact(s, n - len(body))
            if len(body) != n:
                return None
        else:
            body = leftover
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                body += chunk

        if ce == "gzip":
            try:
                body = gzip.decompress(body)
            except Exception:
                return None

        return body

    def resolve_redirect(current_url, location):
        if not location:
            return None
        location = location.strip()

        if location.startswith("http://") or location.startswith("https://"):
            return location

        parsed = parse_url(current_url)
        if not parsed:
            return None
        scheme, host, port, cur_path = parsed
        default_port = 80 if scheme == "http" else 443
        hostpart = host if port == default_port else "{}:{}".format(host, port)

        if location.startswith("/"):
            return "{}://{}{}".format(scheme, hostpart, location)

        base_dir = cur_path.rsplit("/", 1)[0]
        if not base_dir.startswith("/"):
            base_dir = "/" + base_dir
        new_path = (base_dir.rstrip("/") + "/" + location).replace("//", "/")
        return "{}://{}{}".format(scheme, hostpart, new_path)

    def fetch_once(start_url, max_redirects=10):
        current = start_url
        redirects = 0

        while redirects <= max_redirects:
            parsed = parse_url(current)
            if not parsed:
                return None

            scheme, host, port, path = parsed
            default_port = 80 if scheme == "http" else 443
            host_header = host if port == default_port else "{}:{}".format(host, port)

            request = (
                "GET {} HTTP/1.1\r\n"
                "Host: {}\r\n"
                "Connection: close\r\n"
                "User-Agent: curl/7.0\r\n"
                "Accept: */*\r\n"
                "\r\n"
            ).format(path, host_header).encode("ascii", errors="ignore")

            s = None
            try:
                s = connect(scheme, host, port)
                s.sendall(request)

                while True:
                    blob = recv_until(s, b"\r\n\r\n")
                    if b"\r\n\r\n" not in blob:
                        s.close()
                        return None

                    header_part, leftover = blob.split(b"\r\n\r\n", 1)
                    status, headers = parse_headers(header_part)
                    if status is None:
                        s.close()
                        return None

                    if 100 <= status < 200:
                        continue
                    break

                if 300 <= status < 400:
                    new_url = resolve_redirect(current, headers.get("location", ""))
                    s.close()
                    if not new_url:
                        return None
                    current = new_url
                    redirects += 1
                    continue

                if status != 200:
                    s.close()
                    return None

                body = read_body(s, headers, leftover)
                s.close()
                return body

            except Exception:
                try:
                    if s:
                        s.close()
                except Exception:
                    pass
                return None

        return None

    return fetch_once(url)

if __name__ == "__main__":
    sys.stdout.buffer.write(retrieve_url(sys.argv[1]))

