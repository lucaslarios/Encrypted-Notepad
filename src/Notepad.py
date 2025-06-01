
import os    
from tkinter import *
from tkinter import simpledialog
from tkinter.messagebox import *
from tkinter.filedialog import *
from Crypt import Crypt
from tkinter import messagebox
class Notepad:

    __root = Tk()
    __thisWidth = 300
    __thisHeight = 300
    __thisTextArea = Text(__root)
    __thisMenuBar = Menu(__root)
    __thisFileMenu = Menu(__thisMenuBar, tearoff=0)
    __thisEditMenu = Menu(__thisMenuBar, tearoff=0)
    __thisHelpMenu = Menu(__thisMenuBar, tearoff=0)
    __thisEncryptMenu = Menu(__thisMenuBar,tearoff=0)
    __CryptInstance = Crypt()
    __file_crypt_status = 0
    __thisScrollBar = Scrollbar(__thisTextArea)     
    __file = None
    def __init__(self,**kwargs):
        try:
            self.__thisWidth = kwargs['width']
        except KeyError:
            pass

        try:
            self.__thisHeight = kwargs['height']
        except KeyError:
            pass
        self.__root.title("Untitled")

        screenWidth = self.__root.winfo_screenwidth()
        screenHeight = self.__root.winfo_screenheight()

        left = (screenWidth / 2) - (self.__thisWidth / 2) 
        top = (screenHeight / 2) - (self.__thisHeight /2) 
        
        self.__root.geometry('%dx%d+%d+%d' % (self.__thisWidth,
                                              self.__thisHeight,
                                              left, top)) 

        
        self.__root.grid_rowconfigure(0, weight=1)
        self.__root.grid_columnconfigure(0, weight=1)

       
        self.__thisTextArea.grid(sticky = N + E + S + W)
        self.__thisFileMenu.add_command(label="New",command=self.__newFile)    
        self.__thisFileMenu.add_command(label="Open",command=self.__openFile)
        self.__thisFileMenu.add_command(label="Save",command=self.__saveFile)    
        self.__thisFileMenu.add_separator()                                         
        self.__thisFileMenu.add_command(label="Exit",command=self.__quitApplication)
        self.__thisMenuBar.add_cascade(label="File",menu=self.__thisFileMenu)     
        self.__thisHelpMenu.add_command(label="About Notepad",command=self.__showAbout) 
        self.__thisMenuBar.add_cascade(label="Help",menu=self.__thisHelpMenu)
        self.__thisEncryptMenu.add_command(label="Decrypt Text",command=self.__decrypt_routine)
        self.__thisEncryptMenu.add_command(label="Encrypt Text",command=self.__encryt_routine)
        self.__thisMenuBar.add_cascade(label="Encrypt Tools",menu=self.__thisEncryptMenu)
        self.__root.config(menu=self.__thisMenuBar)

        self.__thisScrollBar.pack(side=RIGHT,fill=Y)                           
        self.__thisScrollBar.config(command=self.__thisTextArea.yview)     
        self.__thisTextArea.config(yscrollcommand=self.__thisScrollBar.set)
    


    def __decrypt_routine(self):
        if self.__file_crypt_status != b'\x01':
            messagebox.showinfo("", "Your file is already decrypted.")
            return
        passwd = simpledialog.askstring("Password", "Enter your password to decrypt the file:", show="*")
        if passwd is None:
            return
        if passwd != "":
            crypt_text_bytes = self.__CryptInstance.base64_decode(str_base64=self.__thisTextArea.get(1.0,END))
            
            salt = crypt_text_bytes[1:17]
            key = self.__CryptInstance.derive_key_from_passwd(passwd=passwd,salt=salt)
            iv = crypt_text_bytes[17:33]
            cipherText = crypt_text_bytes[33:]
            plain_text = self.__CryptInstance.decrypt(textEncrypt=cipherText,key=key,iv=iv)
        else:
            messagebox.showinfo("", "Enter a password to decrypt the file.")
            return 
        if plain_text is None:
            messagebox.showinfo("Error", "Wrong Password")   
            return 
        self.__thisTextArea.config(state="normal")
        self.__thisTextArea.delete(1.0,END)
        self.__thisTextArea.insert(1.0,plain_text)
        self.__file_crypt_status = b'\x00'
        
    
    def __encryt_routine(self):
        if self.__file_crypt_status == b'\x01':
            messagebox.showinfo("", "Your file is already encrypted.")
            return
        passwd = simpledialog.askstring("Password", "Create a password to encrypt and decrypt your document:", show="*")
        if passwd is None:
            return
        if passwd != "":
            salt = self.__CryptInstance.generate_salt()
            key = self.__CryptInstance.derive_key_from_passwd(passwd=passwd,salt=salt)
            encrypt_text, iv = self.__CryptInstance.encrypt(textPlain=self.__thisTextArea.get(1.0,END),key=key)
            encrypt_status= b'\x01'
            data_bytes = encrypt_status + salt + iv + encrypt_text
            data_base64 = self.__CryptInstance.base64_encode(data_bytes=data_bytes)
        else:
            messagebox.showinfo("", "Enter a password to encrypt the file")
            return
        if encrypt_text is None:
            messagebox.showinfo("Error", "Error encrypting the file.")
            return 
        self.__thisTextArea.delete(1.0,END)
        self.__thisTextArea.insert(1.0,data_base64)
        self.__file_crypt_status = encrypt_status
        self.__thisTextArea.config(state="disabled")


    def __quitApplication(self):
        self.__root.destroy()

    def __showAbout(self):
        showinfo("INFO","Developer: Lucas Larios")

    def __openFile(self):
        
        self.__file = askopenfilename(defaultextension=".txt",
                                      filetypes=[("All Files","*.*"),
                                        ("Text Documents","*.txt")])

        if self.__file == "":
            self.__file = None
        else:
            self.__root.title(os.path.basename(self.__file))
            file = open(self.__file,"r")
            self.__thisTextArea.delete(1.0,END)
            self.__thisTextArea.insert(1.0,file.read())
            try:
                data_bytes = self.__CryptInstance.base64_decode(str_base64=self.__thisTextArea.get(1.0,END))
                encrypt_status = data_bytes[0:1]
                if encrypt_status == b'\x01':
                    self.__file_crypt_status = encrypt_status
                    self.__thisTextArea.config(state="disabled")
            except:
                pass
            file.close()
    
    
        
    def __newFile(self):
        self.__root.title("New document")
        self.__file = None
        self.__thisTextArea.config(state="normal")
        self.__thisTextArea.delete(1.0,END)
        self.__file_crypt_status =b'\x00'

    def __saveFile(self):

        if self.__file == None:
            self.__file = asksaveasfilename(initialfile='Untitled.LLcrypt',
                                            defaultextension=".LLcrypt",
                                            filetypes=[("All Files","*.*"),
                                                ("Text Documents","*.LLcrypt")])

            if self.__file == "":
                self.__file = None
            else:
                file = open(self.__file,"w")
                print(self.__thisTextArea.get(1.0,END))
                file.write(self.__thisTextArea.get(1.0,END))
                file.close()
                messagebox.showinfo("", "File Saved")
                self.__root.title(os.path.basename(self.__file))
        else:
            file = open(self.__file,"w")
            file.write(self.__thisTextArea.get(1.0,END))
            file.close()
            messagebox.showinfo("", "File Saved")

   
    def run(self):
        self.__root.mainloop()




