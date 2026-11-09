import xml.etree.ElementTree as ET


def main(path: str) -> None:
    root = ET.parse(path).getroot()
    total = 0.0
    for line in root.iter("Line"):
        total += float(line.findtext("Amount") or 0)
    declared = float(root.findtext("DeclaredTotal") or -1)
    if abs(total - declared) < 0.01:
        print("OK")
    else:
        print(f"MISMATCH computed={total:.2f} declared={declared:.2f}")


if __name__ == "__main__":
    import sys

    main(sys.argv[1])
