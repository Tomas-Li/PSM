"""
This is a Free PassWordManager based in the use of a local Encrypted Database in your computer (wich I recomend you keep a safe copy in the cloud) that will be only accesible by an Encryption Password that you must define for every user you want to register.
The first time, you only need to run the program and it will ask you to make a user, set a encryption password and finally to upload your urls <-> psw manually or by a .txt file. Second boot onwards it will ask for the user that you are login into and his encryption password, or to make a new user (last case the steps would be the same as in the first boot).

*You can look for the users' DBs in the following paths depending of your S.O:
    Windows -> C:\PSM
    #! Linux -> ~/.PSM

*
"""

""" TODO and Notes
1)Necesito generar una carpeta donde guarde el registro de los usuarios,
originalmente me gustaria que ese path sea simple como C:\\PSM (|Listo)
2)Una vez recuperada la db debo dar las opciones de agregar, modificar, eliminar, leer .txt (|Listo)
3)A partir de un punto todo deberia estar encerrado en un try, y el finally que lo acompaña tendria que ser el que vuelve a codificar el archivo!(|Listo)
4)Tengo que agregar una forma de cambiar la contraseña o terminar las funciones para escribir y para leer .txt
6)Me falta generar el mail de recuperacion -> ¿COMO??? YO NUNCA TUVE ACCESO A LA CLAVE NO TENGO MANERA DE SABERLA! (X Imposible)
7)Estaria bueno hacer mensajes de confirmacion de tareas! (Esto una vez todo este funcionando) (X Inutil, el codigo es rapidisimo solo voy a meter ruido en consola)
8)Mejorar la impresion del read->ALL
9)Dar las opciones en cada funcion de regresar al main menu (opcion == 'q': return)


Extras:
1)Estaria bueno hacer una version de Windows y de Linux, puedo hacerlo haciendo clases que se instancien segun cual sea el sistema operativo (Creo que solo necesito que eliga el __Base_Path en base al os).
2)Tendria que asegurarme que no puedo pisar a un usuario ya existente en la base de datos (|Listo)
3)Terminar la idea de lectura de datos desde archivos de .txt
4)Poner la contraseña extraida en el clipboard? eso deberia verse con un archivo de configuracion
5)Dejar un opcion en el configure para que se genere una key automatica con fernet para que no tengan que introducir una key al abrir el usuario?


*)Edicion con Kivy/Tkinter?
"""



import os
import base64
import sqlite3
import pyperclip
from difflib import get_close_matches
from configparser import ConfigParser
from sqlite3.dbapi2 import Cursor
from sqlite3.dbapi2 import Error
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC #Keydefinition function -> derives a cryptographic key from the password


class WinUser():

    __BASE_PATH = r"C:\PSM"
    user = None
    fernet = None


    def fernet_generator(self, psw:str) -> None:
        config = ConfigParser()
        config.read('ConfigFile.ini')
        salt = config['key']['salt']
        psw = psw.encode()  #localmente debe ser bytes
        salt = salt.encode() #localmente debe ser bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=320000, #+320,000 minimum by Django
            backend=default_backend())
        self.fernet = Fernet(base64.urlsafe_b64encode(kdf.derive(psw)))


    def encrypt_db(self):
        """Function in charge of encryption"""
        with open(f'{self.__BASE_PATH}{os.sep}{self.user}.psm','rb') as file:
            db_data = file.read()
            db_data_encrypted = self.fernet.encrypt(db_data)
        with open(f'{self.__BASE_PATH}{os.sep}{self.user}.psm','wb') as file:
            file.write(db_data_encrypted)
    

    def decrypt_db(self):
        """Function in charge of decryption"""
        with open(f'{self.__BASE_PATH}{os.sep}{self.user}.psm', 'rb') as file:
            db_data_encrypted = file.read()
            db_data = self.fernet.decrypt(db_data_encrypted)
        with open(f'{self.__BASE_PATH}{os.sep}{self.user}.psm', 'wb') as file:
            file.write(db_data)    


    def remove_entry_db(self) -> None:
        """Function in charge of decrypting the DB, remove an entry from it and finally encrypting the DB once more"""

        try:
            self.decrypt_db()

            conn = sqlite3.connect(f"{self.__BASE_PATH}{os.sep}{self.user}.psm")
            c = conn.cursor()
            c.execute(f"SELECT * FROM {self.user}")
            lst = c.fetchall()
            data = {lst[i][0]:[] for i in range(0,len(lst))}
            for i in range(0,len(lst)):
                data[lst[i][0]].append({lst[i][1]:lst[i][2]})

            urls = []
            for url in lst:
                urls.append(url[0])

            while True:
                print("\tIntroduce the url and account that you want to forget")
                url = input('\t\turl: ')
                if url in urls:
                    break
                else:
                    matches = get_close_matches(url, urls, n=3, cutoff=0.8)
                    print("\t\tThere wasn't an exact match but these were close to your input:")
                    print('\t\t\t', matches)


            print("\t\tAccounts registered in the given url:")
            account_list = []
            for acc in data[url]:
                account_list.append(*acc)
                print("\t\t\t",*acc)
            while True:
                print('\t\tIntroduce the account that you want to remove:')
                account = input('\t\t\taccount: ')
                if account in account_list:
                    break
                else:
                    matches = get_close_matches(account, account_list, n=3, cutoff=0.8)
                    print("\t\t\tThere wasn't an exact match but these were close to your input:")
                    print('\t\t\t\t', matches)        

            c.execute(f"DELETE FROM {self.user} WHERE url=:url AND account=:account", {'url':url, 'account':account})

            conn.commit()
            conn.close()

        finally:
            self.encrypt_db()


    def update_db(self) -> None:
        """Function in charge of decrypting the DB, update information inside the DB and finally encrypting the DB once more"""

        def password_change(c:Cursor,url:str,account:str) -> None:
            print("\tInput the new password")
            password = input("\t\tNew Password: ")
            c.execute(f"UPDATE {self.user} SET password=:password WHERE url=:url AND account=:account", {'password':password, 'url':url, 'account':account})


        try:
            self.decrypt_db()

            conn = sqlite3.connect(f"{self.__BASE_PATH}{os.sep}{self.user}.psm")
            c = conn.cursor()
            c.execute(f"SELECT * FROM {self.user}")
            lst = c.fetchall()
            data = {lst[i][0]:[] for i in range(0,len(lst))}
            for i in range(0,len(lst)):
                data[lst[i][0]].append({lst[i][1]:lst[i][2]})

            urls = []
            for url in lst:
                urls.append(url[0])

            print("\tIntroduce the url that you want to modify")
            while True:
                url = input('\t\turl: ')
                if url in urls:
                    break
                else:
                    matches = get_close_matches(url, urls, n=3, cutoff=0.8)
                    print("\t\tThere wasn't an exact match but these were close to your input:")
                    print('\t\t\t', matches)

            while True:
                print("\t\tAccounts registered in the given url:")
                account_list = []
                for acc in data[url]:
                    account_list.append(*acc)
                    print("\t\t\t",*acc)

                print("\t\t\tWhat do you want to modify?")
                select = input("\t\t\t1-> An account's name ; 2-> A Password: ")
                if (select == '1'):           
                    while True:
                        print("\t\t\t\tInput the account name that you want to modify:")
                        oldaccount = input('\t\t\t\tOld Account: ')
                        if oldaccount in account_list:
                            break
                        else:
                            matches = get_close_matches(oldaccount, account_list, n=3, cutoff=0.8)
                            print("\t\t\t\tThere wasn't an exact match but these were close to your input:")
                            print('\t\t\t\t', matches)
                    

                    print("\t\t\t\tInput the new account: ")
                    account = input('\t\t\t\t\tNew Account: ')
                    
                    
                    c.execute(f"UPDATE {self.user} SET account=:account WHERE url=:url AND account=:oldaccount", {'url':url,'oldaccount':oldaccount ,'account':account})

                    print("\t\t\t\t\tDo you want to modify it's password too?")
                    select = input("\t\t\t\t\t\tY/N: ")
                    while True:
                        if select.lower() == 'y':
                            password_change(c,url,account)
                            break
                        elif select.lower() == 'n':
                            break
                        else:
                            print("\t\t\t\t\tWrong Input")
                            select = input("\t\t\t\t\t\tY/N: ")
                    break

                elif (select == '2'):
                    print("\t\t\tIntroduce which account's password do you want to modify:")
                    while True:
                        account = input("\t\t\t\tAccount: ")
                        if account in account_list:
                            break
                        else:
                            matches = get_close_matches(account, account_list, n=3, cutoff=0.8)
                            print("\t\t\t\tThere wasn't an exact match but these were close to your input:")
                            print('\t\t\t\t', matches)

                    password_change(c,url,account)
                    break

                else:
                    print("\t\t\tWrong Input. Try again\n")


            conn.commit()
            conn.close()

        finally:
            self.encrypt_db()
             

    def insert_db(self) -> None:
        """Function in charge of decrypting the DB, inserting information and finally encrypting the DB once more"""        

        try:
            self.decrypt_db()

            print("\tIn the next three steps introduce the url that you want to save ,then its account and finally its password:")
            url = input('\t\turl: ')
            account = input('\t\tuser: ')
            password = input('\t\tpassword: ')

            conn = sqlite3.connect(f"{self.__BASE_PATH}{os.sep}{self.user}.psm")
            c = conn.cursor()
            c.execute(f"INSERT INTO {self.user} VALUES(:url, :account, :password)",{'url':url,'account':account ,'password':password})
            conn.commit()
            conn.close()

        finally:
            self.encrypt_db()


    def reader_db(self):
        """Function in charge of decrypting the DB, reading the information and finally encrypting the DB once more"""
        
        try:

            self.decrypt_db()

            conn = sqlite3.connect(f"{self.__BASE_PATH}{os.sep}{self.user}.psm")
            c = conn.cursor()
            c.execute(f"SELECT * FROM {self.user}")
            lst = c.fetchall()
            data = {lst[i][0]:[] for i in range(0,len(lst))}
            for i in range(0,len(lst)):
                data[lst[i][0]].append({lst[i][1]:lst[i][2]})
            conn.close()

            print("\tDo you wish to see an especific url or all entries?")
            print("\t1->Url")
            print("\t2->All")
            while True:
                select = input("\t\tinput: ")
                if select == '1':
                    urls = []
                    for url in lst:
                        urls.append(url[0])
                    
                    while True:
                        print("\t\tIntroduce the url that you want to look for:")
                        url = input("\t\t\tUrl: ")
                        if url in urls:
                            print("\t\t\t",data[url])
                            break
                        else:
                            matches = get_close_matches(url, urls, n=3, cutoff=0.8)
                            print("\t\t\tThere wasn't an exact match but these were close to your input:")
                            print('\t\t\t\t', matches)

                    break
                elif select == '2':
                    for d in data:
                        print('\t\t\t',d)
                    break
                else:
                    print("\t\tWrong input\n.\t\tTry again with 1->Url ; 2->All:")

        finally:
            self.encrypt_db()


    def writer_txt(self):
        #!Pendiente
        pass

    def reader_txt(self, path:str):
        #!Pendiente
        pass


    def make_user(self, avoid:list=[None]) -> None:
        """Function in charge of creating the new user file, it's DB and user password. Once that is done it proceeds with the first encryptation"""

        print("\tPlease introduce the name of the new user you want to register:")
        while True:
            self.user = input('\t\tNew User: ')
            if self.user in avoid:
                print('\tThis user already exist! Please choose another name')
            elif self.user == 'NEW_USER':
                print('\tThis is the only invalid username! Please choose another name')
            else:
                break
        conn = sqlite3.connect(f"{self.__BASE_PATH}{os.sep}{self.user}.psm")
        c = conn.cursor()
        c.execute(f"CREATE TABLE if not exists {self.user}(url text, account text, password text)")
        #!c.execute(f"INSERT INTO {self.user} VALUES('-','-','-')")
        conn.commit()
        conn.close()

        print(f"\tNow please introduce the password for {self.user}, I recomend you to write down this password, and keep it safe, as there is no way to recover it (the program never knows your password so there is nothing to do if you loose it):")
        psw = input("\t\tPassword:")

        self.fernet_generator(psw)

        self.encrypt_db()

        print('\n')
        

    def startup(self):
        """Function in charge of selecting the user and password for the session"""
        
        #Checking folder existence
        if not os.path.exists(self.__BASE_PATH):
            os.makedirs(self.__BASE_PATH)

        #Checking .psm files in the folder
        files = [k for k in os.listdir(self.__BASE_PATH) if '.psm' in k]
        files = [k.split('.psm')[0] for k in files]

        #Choosing beetwen users/making a user
        if not files:
            print("No user data found", "Proceding with 'new user' creation:")
            self.make_user()
        else:
            print(f"Posible users to choose from are:")
            for x in files: print(f"-{x}")
            print("*Choose a user from the list or introduce NEW_USER to make a new entry*")
            
            while True:
                self.user = input('\tUser: ')
                if self.user == 'NEW_USER':
                    self.make_user(files)
                    break
                elif not (self.user in files):
                    print("\tUser not found. Try again:")
                else:
                    while True:
                        psw = input(f'\tIntroduce the key for {self.user}: ')
                        self.fernet_generator(psw)
                        try:
                            self.decrypt_db()
                            self.encrypt_db()
                            break
                        except:
                            print("\tWrongPassword. DB couldn't be decrypted")
                    print('\n')
                    break
            


    def main_menu(self):
        func_dicc={'1':self.reader_db,'2':self.insert_db,'3':self.update_db,'4':self.remove_entry_db}
        print(f"Welcome to the main menu {self.user}!")
        while True:
            print("What do you want to do?")
            print("1-> Read the registry")
            print("2-> Input a new entry")
            print("3-> Update an entry")
            print("4-> Remove an entry")
            print("q-> Exit")
            select = input("\tInput: ")
            if select in func_dicc.keys():
                func_dicc[select]()
            elif select.lower() == 'q':
                print('\n')
                exit()
            else:
                print("Wrong Input, Try again:\n")
        


if __name__ == '__main__':
    inst = WinUser()
    inst.startup()
    inst.main_menu()

