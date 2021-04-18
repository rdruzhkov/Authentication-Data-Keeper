import argparse
import logging
import argon2

from argon2 import PasswordHasher
from adkdb import AdkDatabase


def add(args):
    print(f'add called with args: {args}')

    ph = PasswordHasher(
        time_cost=args.iterations,
        memory_cost=args.memory,
        parallelism=args.threads,
        type=argon2.Type.I
    )
    computed_hash = ph.hash(args.password)

    db = AdkDatabase('database.db')
    db.insert(args.login, computed_hash)

    logging.info('OK')


def verify(args):
    print(f'verify called with args: {args}')

    db = AdkDatabase('database.db')
    hash_from_database = db.get_hash(args.login)

    ph = PasswordHasher(
        time_cost=args.iterations,
        memory_cost=args.memory,
        parallelism=args.threads,
        type=argon2.Type.I
    )
    computed_hash = ph.hash(args.password)

    if not ph.verify(computed_hash, hash_from_database):
        logging.debug(f'Incorrect password for login {args.login}')
        logging.info(False)
    else:
        logging.debug(f'Correct password for login {args.login}')
        logging.info(True)


def get_hash(args):
    print(f'get_hash called with args: {args}')

    db = AdkDatabase('database.db')
    hash_ = db.get_hash(args.login)

    logging.debug(f'Hash extracted for login {args.login}: {hash_}')
    logging.info(hash_)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', help='Enables verbose output', default=False,
                        dest='are_debug_messages_enabled')

    subparsers = parser.add_subparsers()

    add_command_parser = subparsers.add_parser('add', help='Adds login and password hash to database')
    add_command_parser.add_argument('login', type=str,
                                    help='Login to add to database')
    add_command_parser.add_argument('password', type=str, help='Password which hash is added to database')
    add_command_parser.add_argument('-i', '--iterations', type=int, choices=range(1, 101),
                                    metavar='{1, ..., 100}',
                                    help='Quantity of password hashing algorithm iterations',
                                    default=2)
    add_command_parser.add_argument('-m', '--memory', type=int, choices=range(102400, 4194305),
                                    metavar='{102400, ..., 4194304}',
                                    help='Quantity of memory to use in kilobytes',
                                    default=102400)
    add_command_parser.add_argument('-t', '--threads', type=int, choices=range(1, 101),
                                    metavar='{1, ..., 100}',
                                    help='Defines the number of parallel threads used by algorithm (changes the resulting hash value)',
                                    default=8)
    add_command_parser.set_defaults(func=add)

    verify_command_parser = subparsers.add_parser('verify',
                                                  help='Verifies that password is corresponding  to given login')
    verify_command_parser.add_argument('login', type=str,
                                       help='Login for which password is checked')
    verify_command_parser.add_argument('password', type=str,
                                       help='Password which is checked for belonging to given login')
    verify_command_parser.set_defaults(func=verify)

    get_hash_command_parser = subparsers.add_parser('get_hash', help='Gets hash value for given login from database')

    get_hash_command_parser.set_defaults(func=get_hash)
    get_hash_command_parser.add_argument('login', type=str,
                                         help='Login for which hash is extracted')

    args = parser.parse_args()

    if args.are_debug_messages_enabled:
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
        logging.debug('Debug messages are enabled.')
    else:
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()
