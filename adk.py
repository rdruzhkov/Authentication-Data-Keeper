import logging
import re
import sqlite3
import tkinter as tk
from tkinter import messagebox

import argon2

from argon2 import PasswordHasher
from adkdb import AdkDatabase, AdkException


PADDING_X = 3
PADDING_Y = 3

ITERATIONS_MIN = 1
ITERATIONS_MAX = 100

MEMORY_MIN = 102400
MEMORY_MAX = 4194305

THREADS_MIN = 1
THREADS_MAX = 100


class ValidationError(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class MainWindow(tk.Tk):

    class MainFrame(tk.Frame):

        def __init__(self, master):
            super().__init__(master)

            self.__is_password_shown = False

            self.__label_login = tk.Label(self, text="Login:")
            self.__label_login.grid(row=0, column=0, sticky="E", padx=PADDING_X, pady=PADDING_Y)
            self.__entry_login = tk.Entry(self, width=45)
            self.__entry_login.grid(row=0, column=1, sticky="W", columnspan=3, padx=PADDING_X, pady=PADDING_Y)

            self.__label_password = tk.Label(self, text="Password:")
            self.__label_password.grid(row=1, column=0, sticky="E", padx=PADDING_X, pady=PADDING_Y)
            self.__entry_password = tk.Entry(self, width=31, show="*",)
            self.__entry_password.grid(row=1, column=1, sticky="W", columnspan=2, padx=PADDING_X, pady=PADDING_Y)

            self.__label_iterations = tk.Label(self, text="Iterations:")
            self.__label_iterations.grid(row=0, column=4, sticky="E", padx=PADDING_X, pady=PADDING_Y)
            self.__spinbox_iterations = tk.Spinbox(self, from_=1, to=100, width=20)
            self.__spinbox_iterations.grid(row=0, column=5, sticky="W", padx=PADDING_X, pady=PADDING_Y)
            self.__spinbox_iterations.delete(0)
            self.__spinbox_iterations.insert(0, '2')

            self.__label_memory = tk.Label(self, text="Memory:")
            self.__label_memory.grid(row=1, column=4, sticky="E", padx=PADDING_X, pady=PADDING_Y)
            self.__spinbox_memory = tk.Spinbox(self, from_=102400, to=4194305, width=20)
            self.__spinbox_memory.grid(row=1, column=5, sticky="W", padx=PADDING_X, pady=PADDING_Y)

            self.__label_threads = tk.Label(self, text="Threads:")
            self.__label_threads.grid(row=2, column=4, sticky="E", padx=PADDING_X, pady=PADDING_Y)
            self.__spinbox_threads = tk.Spinbox(self, from_=1, to=100, width=20)
            self.__spinbox_threads.grid(row=2, column=5, sticky="W", padx=PADDING_X, pady=PADDING_Y)
            self.__spinbox_threads.delete(0)
            self.__spinbox_threads.insert(0, '8')

            self.__button_add = tk.Button(self, text='Add', width=10, command=self.__button_add_handler)
            self.__button_add.grid(row=2, column=1, sticky='NW', padx=PADDING_X, pady=PADDING_Y)

            self.__button_get = tk.Button(self, text='Get', width=10, command=self.__button_get_handler)
            self.__button_get.grid(row=2, column=2, sticky='NW', padx=PADDING_X, pady=PADDING_Y)

            self.__button_verify = tk.Button(self, text='Verify', width=10, command=self.__button_verify_handler)
            self.__button_verify.grid(row=2, column=3, sticky='NW', padx=PADDING_X, pady=PADDING_Y)

            self.__button_show_password = tk.Button(self, text='Show', width=10, command=self.__button_show_password_handler)
            self.__button_show_password.grid(row=1, column=3, sticky='NW', padx=PADDING_X, pady=PADDING_Y)

        def __validate_and_get_login(self):
            login = self.__entry_login.get()
            if not login:
                raise ValidationError('Please fill login field.')

            if not re.fullmatch(r"^[a-zA-Z0-9]+$", login) or \
               not 4 <= len(login) <= 20:
                raise ValidationError('Login must contain letters or numerals and be more then 4 and less then 20 characters')

            return login

        def __validate_and_get_password(self):
            password = self.__entry_password.get()
            if not password:
                raise ValidationError('Please fill password field.')

            if not re.search(r"[a-z]", password) or \
               not re.search(r"[A-Z]", password) or \
               not re.search(r"[0-9]", password) or \
               not re.search(r"[!#$%&'()*+,-./[\\\]^_`{|}~\"r]", password) or \
               not re.fullmatch(r"[a-zA-Z0-9!#$%&'()*+,-./[\\\]^_`{|}~\"r]+", password) or \
               not 8 <= len(password) <= 30:
                raise ValidationError(
'''
Password must contain small and big letters, numerals and special characters, password also must be more 
then 8 and less then 30 characters.
'''
)

            return password

        def __validate_and_get_iterations(self):
            iterations = self.__spinbox_iterations.get()
            if not iterations:
                raise ValidationError('Please fill iterations field.')

            try:
                iterations = int(iterations)
                if not ITERATIONS_MIN <= iterations <= ITERATIONS_MAX:
                    raise Exception()

            except Exception as e:
                raise ValidationError(F'Iterations field must contain value from {ITERATIONS_MIN} to {ITERATIONS_MAX}')

            return iterations

        def __validate_and_get_memory(self):
            memory = self.__spinbox_memory.get()
            if not memory:
                raise ValidationError('Please fill memory field.')

            try:
                memory = int(memory)
                if not MEMORY_MIN <= memory <= MEMORY_MAX:
                    raise Exception()

            except Exception as e:
                raise ValidationError(f'Memory field must contain value from {MEMORY_MIN} to {MEMORY_MAX}')

            return memory

        def __validate_and_get_threads(self):
            threads = self.__spinbox_threads.get()
            if not threads:
                raise ValidationError('Please fill threads field.')

            try:
                threads = int(threads)
                if not THREADS_MIN <= threads <= THREADS_MAX:
                    raise Exception()

            except Exception as e:
                raise ValidationError(f'Threads field must contain value from {THREADS_MIN} to {THREADS_MAX}')

            return threads

        def __button_show_password_handler(self):
            if self.__is_password_shown:
                self.__entry_password.config(show="*")
            else:
                self.__entry_password.config(show="")

            self.__is_password_shown = not self.__is_password_shown

        def __button_add_handler(self):
            logging.debug('__button_add_handler called')

            try:
                login = self.__validate_and_get_login()
                password = self.__validate_and_get_password()
                threads = self.__validate_and_get_threads()
                memory = self.__validate_and_get_memory()
                iterations = self.__validate_and_get_iterations()

                ph = PasswordHasher(
                        time_cost=iterations,
                        memory_cost=memory,
                        parallelism=threads,
                        type=argon2.Type.I
                    )
                computed_hash = ph.hash(password)

                db = AdkDatabase('database.db')

                try:
                    db.insert(login, computed_hash)
                except sqlite3.IntegrityError:
                    messagebox.showerror('Entity error', f'Login "{login}" is already present in database')
                    return

                messagebox.showinfo('Information', f'Success')

            except ValidationError as validation_error:
                messagebox.showerror('Validation error', str(validation_error))

            except Exception as e:
                messagebox.showerror('Error', 'Unknown error')

        def __button_verify_handler(self):
            logging.debug('__button_verify_handler called')

            try:
                login = self.__validate_and_get_login()
                password = self.__validate_and_get_password()

                db = AdkDatabase('database.db')

                try:
                    hash_from_database = db.get_hash(login)
                except AdkException as adk_exception:
                    messagebox.showerror('Error', str(adk_exception))
                    return

                ph = PasswordHasher()

                try:
                    ph.verify(hash_from_database, password)
                    messagebox.showinfo('Information', f'Provided credentials are correct')
                except argon2.exceptions.VerifyMismatchError:
                    messagebox.showinfo('Information', f'Provided credentials are NOT correct')

            except ValidationError as validation_error:
                messagebox.showerror('Validation error', str(validation_error))

            except Exception as e:
                messagebox.showerror('Error', 'Unknown error')

        def __button_get_handler(self):
            logging.debug('__button_get_handler called')

            try:
                login = self.__validate_and_get_login()

                db = AdkDatabase('database.db')

                try:
                    hash_ = db.get_hash(login)
                except AdkException as e:
                    messagebox.showinfo('Error', str(e))
                    return

                logging.debug(f'Hash extracted for login {login}: {hash_}')
                messagebox.showinfo('Information', f'Hash extracted for login {login}: {hash_}')

            except ValidationError as validation_error:
                messagebox.showerror('Validation error', str(validation_error))

            except Exception as e:
                messagebox.showerror('Error', 'Unknown error')

    def __init__(self):
        super().__init__()

        self.title('Authentication Data Keeper')
        self.resizable(False, False)

        self.__frame_main = self.MainFrame(self)
        self.__frame_main.grid(row=0, column=0, padx=PADDING_X, pady=PADDING_Y)


if __name__ == '__main__':
    logging.basicConfig(
        format='[%(levelname)s]: %(message)s',
        level=logging.DEBUG)

    main_window = MainWindow()
    main_window.mainloop()
