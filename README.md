This is a Free PasswordManager based in the use of a local Encrypted Database in your computer that will be only accesible by an Encryption Password that you must define for every user you want to register.
The first time that you use the software, you only need to run it and it will ask you to make a user and set a encryption password, then you can upload your passwords manually or by a .txt file. Second boot onwards it will ask for the user that you are login into and his encryption password, or to make a new user (last case the steps would be the same as in the first boot).

Installation:
1. Have python installed
2. Clone the repository (or just download the ConfigFile.ini and main.py)
3. Use pip to install cryptography or open a console in the clone folder and run: pip install . (it will install the dependencies listed in the requeriments.txt -> cryptography is the only one)
4. You are ready to try PSM 


If you are a windows user I recommend you to make a shortcut to run PSM from it. For this just:
1. Go to your desktop -> RMB -> New -> shortcut
2. For path you are going to choose the path to your python executable (the one with cryptography) and separated by a withe space between quotes the path to main.py
    Example of the final path: C:\Users\tomi_\AppData\Local\Programs\Python\Python39\python.exe "E:\Codes\Python\PSM\main.py"
3. Check if the shortcut is working. If it is you are done.


Some notes about the software:
1. You can modify the default main directory of the application from the ConfigFile.ini (this is where you have to look for the users' DBs). The defualt paths are S.O:
    Windows -> C:\PSM
    Linux -> ~/.PSM

2. The encryption used for the DB is based in the salt (wich you can modify from the ConfigFile.ini) and in the password defined during the user creation.

3. If you want to load your password to a user's DB the only thing that you will need is .txt file with the estructure of \<url> \<account> \<password> (one entry per line)

4. Keep a copy of your salt and password in somewhere safe (besides your brain) as if you forget them there is no way to recover neither of them.

5. Ideally you want to keep the main directory sincronized with a cloud service. The password inside the DB are protected by the encryptation so even if someone could get inside your cloud they won't be able to get your passwords, and if you have a copy in the cloud if something where to happen to your physical drive you wont loose your passwords, just download your user's DB and you are ready to go.

