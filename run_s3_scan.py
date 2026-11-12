import json
from cloudguard.scanners.s3_scanner import S3Scanner

if __name__ == "__main__":
    scanner = S3Scanner()
    results = scanner.scan()
    print(json.dumps(results, indent=4, default=str))
