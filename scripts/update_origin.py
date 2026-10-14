"""Legacy in-place origin updating is unavailable; case evidence is preserved."""
import argparse


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog='Create a separate case with paw full INPUT --no-egress. '
               'Controlled network enrichment remains deferred.')
    parser.parse_args()
    parser.exit(1, 'Report update unavailable: create a new analysis case; '
                   'existing sealed evidence is preserved\n')


if __name__ == '__main__':
    main()
