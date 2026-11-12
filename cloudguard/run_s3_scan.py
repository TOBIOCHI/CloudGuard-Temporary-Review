
import json
from cloudguard.scanners.s3_scanner import scan_s3

if __name__ == "__main__":
    results = scan_s3()
    print(json.dumps(results, indent=4, default=str))
