"""
This is a Free PassWordManager based in the use of a local Encrypted Database in your computer (wich I recomend you keep a safe copy in the cloud) that will be only accesible by an Encryption Password that you must define for every user you want to register.
The first time, you only need to run the program and it will ask you to make a user, set a encryption password and finally to upload your urls <-> psw manually or by a .txt file. Second boot onwards it will ask for the user that you are login into and his encryption password, or to make a new user (last case the steps would be the same as in the first boot).

*You can look for the users' DBs in the following paths depending of your S.O:
    Windows -> C:\PSM
    #! Linux -> ~/.PSM

*
"""

""" TODO and Notes
#Asymmetric encryption -> rsa
#Symmetric encryption -> cryptography
#!Que tal si encripto las contraseñas que guardo y no toda la database???entonces solo desencripto ese unico dato (Pensarlo)
#!FALTA TODO EL SISTEMA DE CREACION DE KEYS
#!SALT deberia ser leida desde un archivo de configuracion
#!Encerrar todo en try,finally statements para reencriptar siempre la base!
#!Es muyyy posible que si trato de desencriptar sin la contraseña adecuada y el resto del codigo se ejecuta termine rompiendo la db al luego reencriptar lo encriptado con la mala contraseña! debo buscar una forma de evitar esto!
    No es problema. Con la forma en que se hizo con cryptography si la contraseña es incorrecta se levanta un excepcion (InvalidSignature ó InvalidToken)

1)Necesito generar una carpeta donde guarde el registro de los usuarios,
originalmente me gustaria que ese path sea simple como C:\\PSM (|Listo)
2)Una vez recuperada la db debo dar las opciones de agregar, modificar, eliminar, leer .txt (|Listo)
3)A partir de un punto todo deberia estar encerrado en un try, y el finally que lo acompaña tendria que ser el que vuelve a codificar el archivo!
4)Tengo que agregar una forma de cambiar la contraseña 
6)Me falta generar el mail de recuperacion -> ¿COMO??? YO NUNCA TUVE ACCESO A LA CLAVE NO TENGO MANERA DE SABERLA!
7)Estaria bueno hacer mensajes de confirmacion de tareas! (Esto una vez todo este funcionando)


Extras:
1)Estaria bueno hacer una version de Windows y de Linux, puedo hacerlo haciendo clases que se instancien segun cual sea el sistema operativo (Creo que solo necesito que eliga el __Base_Path en base al os). En un primer momento voy a hacerlo para windows
2)Tendria que asegurarme que no puedo pisar a un usuario ya existente en la base de datos (|Listo)
3)Terminar la idea de lectura de datos desde archivos de .txt
4)Poner la contraseña extraida en el clipboard? eso deberia verse con un archivo de configuracion
5)Dejar un opcion en el configure para que se genere una key automatica con fernet para que no tengan que introducir una key al abrir el usuario?


*)Edicion con Kivy/Tkinter?
"""


from difflib import get_close_matches
import os
import sqlite3
from sqlite3.dbapi2 import Cursor


class WinUser():

    __BASE_PATH = r"C:\PSM"
    user = None
    psw = None

    def remove_entry_db(self, user:str, psw:str) -> None:
        #!Decrypt Part

        conn = sqlite3.connect(f"{self.__BASE_PATH}{os.sep}{user}.psm")
        c = conn.cursor()
        c.execute(f"SELECT * FROM {user}")
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
            account = input('\t\taccount: ')
            if account in account_list:
                break
            else:
                matches = get_close_matches(account, account_list, n=3, cutoff=0.8)
                print("\t\t\tThere wasn't an exact match but these were close to your input:")
                print('\t\t\t\t', matches)        

        c.execute(f"DELETE FROM {user} WHERE url=:url AND account=:account", {'url':url, 'account':account})

        conn.commit()
        conn.close()

        #!Encrypt part


    def update_db(self, user:str, psw:str) -> None:
        def password_change(c:Cursor,user:str,url:str,account:str) -> None:
            print("\tInput the new password")
            password = input("\t\tNew Password: ")
            c.execute(f"UPDATE {user} SET password=:password WHERE url=:url AND account=:account", {'password':password, 'url':url, 'account':account})


        #!Decrypt Part

        conn = sqlite3.connect(f"{self.__BASE_PATH}{os.sep}{user}.psm")
        c = conn.cursor()
        c.execute(f"SELECT * FROM {user}")
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

        print("\t\tAccounts registered in the given url:")
        account_list = []
        for acc in data[url]:
            account_list.append(*acc)
            print("\t\t\t",*acc)

        print("\t\t\tWhat do you want to modify?")
        select = input("\t\t\t1->An account ; 2->A Password: ")
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
            
            
            c.execute(f"UPDATE {user} SET account=:account WHERE url=:url AND account=:oldaccount", {'url':url,'oldaccount':oldaccount ,'account':account})

            print("\t\t\t\t\tDo you want to modify it's password too?")
            select = input("\t\t\t\t\t\tY/N: ")
            while True:
                if select.lower() == 'y':
                    password_change(c,user,url,account)
                    break
                elif select.lower() == 'n':
                    break
                else:
                    print("\t\t\t\t\tWrong Input")
                    select = input("\t\t\t\t\t\tY/N")

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

            password_change(c,user,url,account)

        else:
            print("\t\t\tWrong Input. Returning to main menu...\n")
            return

        conn.commit()
        conn.close()

        #!Encrypt part
             

    def insert_db(self,user:str,psw:str) -> None:
        #!Decrypt Part

        print("\tIn the next three steps introduce the url that you want to save ,then its account and finally its password:")
        url = input('\t\turl: ')
        account = input('\t\tuser: ')
        password = input('\t\tpassword: ')

        conn = sqlite3.connect(f"{self.__BASE_PATH}{os.sep}{user}.psm")
        c = conn.cursor()
        c.execute(f"INSERT INTO {user} VALUES(:url, :account, :password)",{'url':url,'account':account ,'password':password})
        conn.commit()
        conn.close()

        #!Encrypt Part

    def reader_db(self, user:str, psw:str):
        ###Have to decrypt the db
        ###Have to return loaded table
        ###Have to encrypt once again
        
        #! decrypt Part #!

        conn = sqlite3.connect(f"{self.__BASE_PATH}{os.sep}{user}.psm")
        c = conn.cursor()
        c.execute(f"SELECT * FROM {user}")
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

        #!Encryption part


    def reader_txt(self, path:str):
        pass


    def make_user(self, avoid:list=None):
        ###It has to create and encrypt the db 
        print("\tPlease introduce the name of the new user you want to register:")
        while True:
            user = input('\t\tNew User: ')
            if user in avoid:
                print('\tThis user already exist! Please choose another name')
            elif user == 'NEW_USER':
                print('\tThis is the only invalid username! Please choose another name')
            else:
                break
        conn = sqlite3.connect(f"{self.__BASE_PATH}{os.sep}{user}.psm")
        c = conn.cursor()
        c.execute(f"CREATE TABLE if not exists {user}(url text, account text, password text)")
        conn.commit()
        conn.close()

        #!Create the Key and encrypt the db 

        print('\n')
        return user


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
            user = input('\tUser: ')
            if user == 'NEW_USER':
                user = self.make_user(files)
            else:
                while not (user in files):
                    user = input('\tUser not found. Try again: ')
                    if user == 'NEW_USER':
                        user = self.make_user()
                        break
            
            #!A partir de aca tendria que envolver las siguientes dos lineas en un while para la funcion de testeo de encriptacion!
            psw = input(f'\tIntroduce the key for {user}: ')
            print('\nCaution: If the input key was wrong the data that will be show now onwards will be garbage. Please restart the app if it happend by accident\n' )
            self.user = user
            self.psw = psw


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
                func_dicc[select](self.user,self.psw)
            elif select.lower() == 'q':
                print('\n')
                exit()
            else:
                print("Wrong Input, Try again:\n")
        


if __name__ == '__main__':
    inst = WinUser()
    inst.startup()
    inst.main_menu()

