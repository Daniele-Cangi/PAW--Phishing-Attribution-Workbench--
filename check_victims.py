#!/usr/bin/env python3
"""Legacy diagnostic for complete, unverified stored Sentinel interaction rows."""
import argparse
import json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        from paw.sentinel import CampaignDatabase, SentinelConfig

        database = CampaignDatabase(SentinelConfig().get('storage.database_path'), read_only=True)
        report = database.get_victim_statistics()
        output = json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False)
    except Exception as error:
        parser.exit(1, f'error: {error}\n')
    print(output)


if __name__ == '__main__':
    main()
