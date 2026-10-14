"""Legacy checkout alias for the passive `paw monitor list` command."""
import sys


def main():
    from paw.__main__ import main as cli_main

    sys.argv = ['paw', 'monitor', 'list', *sys.argv[1:]]
    cli_main()


if __name__ == '__main__':
    main()
