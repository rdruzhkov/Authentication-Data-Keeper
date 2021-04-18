
import sqlite3
import logging
from contextlib import contextmanager


@contextmanager
def cursor(database_name):
    try:
        con = sqlite3.connect(database_name)
        cur = con.cursor()
        yield cur
    finally:
        con.commit()
        con.close()


class AdkDatabase:

    def __init__(self, database_name):
        self.__database_name = database_name
        self.__table_name = 'Auth'

        if not self.__is_table_present():
            logging.debug('Database table is not present.')
            self.__create_table()

    def __is_table_present(self):
        with cursor(self.__database_name) as cur:

            cur.execute(
                f''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='{self.__table_name}' '''
            )
            if cur.fetchone()[0] == 1:
                is_table_present = True
            else:
                is_table_present = False

        return is_table_present

    def __create_table(self):
        logging.debug('Creating table...')
        with cursor(self.__database_name) as cur:
            cur.execute(f'create table {self.__table_name}(login text unique, passwordHash text)')
        logging.debug('Table created...')

    def insert(self, login: str, password_hash: str):
        logging.debug(f'Inserting pair ({login}, {password_hash}) into database.')
        with cursor(self.__database_name) as cur:
            cur.execute(f'insert into {self.__table_name} values (?, ?)', (login, password_hash))

    def get_hash(self, login: str):
        logging.debug(f'Extracting password hash for login: {login}.')
        with cursor(self.__database_name) as cur:
            cur.execute(f'select passwordHash from {self.__table_name} where login=?', (login, ))
            result = cur.fetchone()[0]

        logging.debug(f'Extracted password hash for login {login}: {result}.')
        return result
