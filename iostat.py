import sys, os

def humanSize(size):
    kb = 1024
    mb = 1024 * kb
    gb = 1024 * mb
    tb = 1024 * gb
    pb = 1024 * tb
    eb = 1024 * pb
    if size == 0:
        return "0 byte"
    elif size >= eb:
        return "{:.5f} {}".format(float(size) / eb, "EiB")
    elif size >= pb:
        return "{:.4f} {}".format(float(size) / pb, "PiB")
    elif size >= tb:
        return "{:.3f} {}".format(float(size) / tb, "TiB")
    elif size >= gb:
        return "{:.2f} {}".format(float(size) / gb, "GiB")
    elif size >= mb:
        return "{:.1f} {}".format(float(size) / mb, "MiB")
    elif size >= kb:
        return "{:.0f} {}".format(size / kb, "KiB")
    else:
        return "{} {}".format(size, "bytes")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: {} pid".format(sys.argv[0]))
        exit (1)
    pid = sys.argv[1]
    path = "/proc/{}/io".format(pid)
    if not os.path.exists(path):
        print("{} does not exist".format(path))
        exit (1)
    f = open(path)
    for line in f:
        stat, stat_bytes = line.strip().split(" ")
        print("{} {}".format(stat, humanSize(int(stat_bytes))))
