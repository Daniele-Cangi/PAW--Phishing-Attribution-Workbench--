#!/usr/bin/env python3
"""Legacy diagnostic for complete, unverified stored Sentinel interaction rows."""
import argparse
import json
from pathlib import Path


def _database_path():
    config = Path('sentinel_config.json')
    try:
        config.lstat()
    except FileNotFoundError:
        return 'sentinel.db'

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate key in Sentinel configuration: ' + key)
            result[key] = value
        return result

    with config.open('r', encoding='utf-8') as source:
        value = json.load(source, object_pairs_hook=unique_object)
    storage = value.get('storage') if isinstance(value, dict) else None
    database = storage.get('database_path') if isinstance(storage, dict) else None
    if not isinstance(database, str) or not database.strip():
        raise ValueError('Sentinel configuration requires a nonblank storage.database_path')
    return database


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        from paw.sentinel import CampaignDatabase

        database = CampaignDatabase(_database_path(), read_only=True)
        report = database.get_victim_statistics()
        output = json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False)
    except Exception as error:
        parser.exit(1, f'error: {error}\n')
    print(output)


if __name__ == '__main__':
    main()
