#!/usr/bin/env python3
"""
Cliente FTP com interface gráfica utilizando Tkinter.

Este script implementa uma interface gráfica para um cliente FTP simples,
permitindo operações como login, listagem de arquivos, upload, download,
navegação de diretórios, criação e remoção de pastas, e logout.
Utiliza sockets para comunicação com o servidor FTP e threading para
manipulação de operações assíncronas.
"""

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import socket
import threading
import os
from PIL import Image, ImageTk


class MyFTPClientGUI:
    """
    Classe que implementa a interface gráfica do cliente FTP.
    """
    def __init__(self, master: tk.Tk):
        self.master = master
        self.master.title("MyFTP Client")
        self.master.geometry("900x600")  # Tamanho aumentado da janela
        self.connection = None

        # Configuração do tema ttk para um visual moderno
        style = ttk.Style()
        style.theme_use('clam')

        style.configure(
            'TButton',
            font=('Segoe UI', 11),  # Fonte aumentada
            padding=8,               # Padding aumentado
            background='#D3D3D3',    # Cinza claro
            foreground='black'
        )
        style.map(
            'TButton',
            background=[('active', '#BFBFBF')]  # Cinza mais escuro ao clicar
        )

        style.configure(
            'Custom.TButton',
            background='#D3D3D3',
            foreground='black',
            font=('Segoe UI', 12, 'bold'),  # Fonte maior e em negrito para botões principais
            padding=10                     # Mais padding para botões importantes
        )
        style.map(
            'Custom.TButton',
            background=[('active', '#BFBFBF')]
        )

        style.configure('TLabel', font=('Segoe UI', 11))  # Fonte dos rótulos aumentada
        style.configure('TEntry', font=('Segoe UI', 11))  # Fonte dos campos de entrada aumentada
        style.configure('Treeview', font=('Segoe UI', 11), rowheight=30)  # Altura das linhas da Treeview
        style.configure('Treeview.Heading', font=('Segoe UI', 11, 'bold'))

        # Configuração do fundo da janela e dos frames
        self.master.configure(bg="white")
        style.configure("TFrame", background="white")
        style.configure("TLabel", background="white")

        # Frame container para alternar entre telas (login e principal)
        self.container = ttk.Frame(master)
        self.container.pack(expand=True, fill='both')

        # =================== FRAME DE LOGIN ===================
        self.login_frame = ttk.Frame(self.container)
        self.login_frame.place(relx=0.5, rely=0.5, anchor='center')

        # Título da tela de login
        ttk.Label(
            self.login_frame,
            text="MyFTP Login",
            font=('Segoe UI', 18, 'bold')
        ).grid(row=0, column=0, columnspan=2, pady=20)

        # Campo para informar o IP do servidor
        ttk.Label(
            self.login_frame,
            text="Servidor IP:",
            font=('Segoe UI', 12)
        ).grid(row=1, column=0, sticky='e', padx=10, pady=8)
        self.server_ip_entry = ttk.Entry(self.login_frame, font=('Segoe UI', 12), width=25)
        self.server_ip_entry.grid(row=1, column=1, padx=10, pady=8)
        self.server_ip_entry.insert(0, "127.0.0.1")

        # Campo para informar a porta
        ttk.Label(
            self.login_frame,
            text="Porta:",
            font=('Segoe UI', 12)
        ).grid(row=2, column=0, sticky='e', padx=10, pady=8)
        self.port_entry = ttk.Entry(self.login_frame, font=('Segoe UI', 12), width=25)
        self.port_entry.grid(row=2, column=1, padx=10, pady=8)
        self.port_entry.insert(0, "2121")

        # Campo para informar o usuário
        ttk.Label(
            self.login_frame,
            text="Usuário:",
            font=('Segoe UI', 12)
        ).grid(row=3, column=0, sticky='e', padx=10, pady=8)
        self.user_entry = ttk.Entry(self.login_frame, font=('Segoe UI', 12), width=25)
        self.user_entry.grid(row=3, column=1, padx=10, pady=8)

        # Campo para informar a senha (oculta)
        ttk.Label(
            self.login_frame,
            text="Senha:",
            font=('Segoe UI', 12)
        ).grid(row=4, column=0, sticky='e', padx=10, pady=8)
        self.pass_entry = ttk.Entry(self.login_frame, show="*", font=('Segoe UI', 12), width=25)
        self.pass_entry.grid(row=4, column=1, padx=10, pady=8)

        # Frame para centralizar o botão de login
        login_btn_frame = ttk.Frame(self.login_frame)
        login_btn_frame.grid(row=5, column=0, columnspan=2, pady=20)
        self.login_button = ttk.Button(
            login_btn_frame,
            text="Login",
            command=self.login,
            style='Custom.TButton',
            width=15
        )
        self.login_button.pack(pady=5)

        # Rótulo de rodapé na tela de login
        self.login_footer_label = ttk.Label(
            self.master,
            text="Desenvolvido por Thaís e Thalles",
            font=('Segoe UI', 9)
        )
        self.login_footer_label.place(relx=0.5, rely=0.98, anchor='s')
        # =======================================================

        # =================== FRAME PRINCIPAL ===================
        self.main_frame = ttk.Frame(self.container)

        # Sidebar para os botões de comando
        self.sidebar = ttk.Frame(self.main_frame, width=200)
        self.sidebar.grid(row=0, column=0, sticky='ns', padx=(10, 5), pady=10)
        self.sidebar.pack_propagate(False)  # Impede que a sidebar encolha

        # Frame para exibição dos arquivos (Treeview)
        self.file_frame = ttk.Frame(self.main_frame, padding=10)
        self.file_frame.grid(row=0, column=1, sticky='nsew', padx=(5, 10), pady=10)

        # Configuração de responsividade da interface principal
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(0, weight=1)

        # Treeview com barra de rolagem para listar arquivos
        self.scrollbar = ttk.Scrollbar(self.file_frame)
        self.scrollbar.pack(side='right', fill='y')
        self.ls_tree = ttk.Treeview(
            self.file_frame,
            columns=("Name", "Type", "Size"),
            show="headings",
            yscrollcommand=self.scrollbar.set
        )
        self.ls_tree.heading("Name", text="Nome")
        self.ls_tree.heading("Type", text="Tipo")
        self.ls_tree.heading("Size", text="Tamanho")
        self.ls_tree.column("Name", width=250)
        self.ls_tree.column("Type", width=100)
        self.ls_tree.column("Size", width=120)
        self.ls_tree.pack(expand=True, fill='both')
        self.scrollbar.config(command=self.ls_tree.yview)

        # Carregamento dos ícones para os botões da sidebar
        def load_icon(path):
            try:
                return ImageTk.PhotoImage(Image.open(path).resize((24, 24)))
            except Exception as e:
                print(f"Error loading icon {path}: {e}")
                return None

        self.upload_icon = load_icon("images/upload.png")
        self.download_icon = load_icon("images/download.png")
        self.folder_icon = load_icon("images/folder.png")
        self.back_icon = load_icon("images/back.png")
        self.create_icon = load_icon("images/create.png")
        self.delete_icon = load_icon("images/delete.png")
        self.logout_icon = load_icon("images/logout.png")
        self.reload_icon = load_icon("images/reload.png")

        # Definição dos botões com suas funções e ícones
        btn_options = [
            ("Atualizar Lista (ls)", self.ls_command, self.reload_icon),
            ("Upload (put)", self.put_command, self.upload_icon),
            ("Upload Múltiplo", self.put_multiple_command, self.upload_icon),
            ("Download (get)", self.get_command, self.download_icon),
            ("Mudar Diretório (cd)", self.cd_command, self.folder_icon),
            ("Voltar Diretório (cd..)", self.cd_up_command, self.back_icon),
            ("Criar Pasta (mkdir)", self.mkdir_command, self.create_icon),
            ("Remover Pasta (rmdir)", self.rmdir_command, self.delete_icon),
            ("Logout", self.logout, self.logout_icon)
        ]
        for text, cmd, icon in btn_options:
            if icon:
                btn = ttk.Button(self.sidebar, text=text, image=icon, compound='left', command=cmd, width=20)
            else:
                btn = ttk.Button(self.sidebar, text=text, command=cmd, width=20)
            btn.pack(fill='x', padx=5, pady=6)

    def login(self) -> None:
        """
        Realiza o login no servidor FTP.
        """
        server_ip = self.server_ip_entry.get()
        port = int(self.port_entry.get())
        user = self.user_entry.get()
        pwd = self.pass_entry.get()

        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.connect((server_ip, port))
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível conectar ao servidor: {e}")
            return

        login_command = f"login {user} {pwd}"
        self.connection.sendall(login_command.encode())
        response = self.connection.recv(1024).decode()
        if "bem-sucedido" in response:
            messagebox.showinfo("Login", "Login realizado com sucesso!")
            self.login_frame.destroy()         # Remove a tela de login
            self.login_footer_label.destroy()    # Remove o rodapé do login
            self.main_frame.pack(expand=True, fill='both')
            self.ls_command()  # Atualiza a lista de arquivos
        else:
            messagebox.showerror("Login", response)

    def ls_command(self) -> None:
        """
        Lista os arquivos no diretório atual do servidor FTP.
        """
        if not self.connection:
            messagebox.showerror("Erro", "Não há conexão ativa com o servidor.")
            return
        try:
            self.connection.sendall("ls".encode())
            response = self.connection.recv(4096).decode()
            # Limpa a Treeview antes de inserir os novos dados
            for item in self.ls_tree.get_children():
                self.ls_tree.delete(item)
            # Processa cada linha da resposta e insere na Treeview
            for line in response.split("\n"):
                if line:
                    parts = line.split(":")
                    if len(parts) == 3:
                        name, type_, size = parts
                        self.ls_tree.insert("", "end", values=(name, type_, size))
                    else:
                        print(f"Linha com formato inválido: {line}")
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def disable_buttons(self) -> None:
        """
        Desabilita os botões na sidebar durante operações críticas.
        """
        for child in self.sidebar.winfo_children():
            if isinstance(child, ttk.Button):
                child.config(state='disabled')

    def enable_buttons(self) -> None:
        """
        Habilita os botões na sidebar após a conclusão de uma operação.
        """
        for child in self.sidebar.winfo_children():
            if isinstance(child, ttk.Button):
                child.config(state='normal')

    def put_file_thread(self, filepath: str) -> None:
        """
        Executa o upload de um único arquivo em uma thread separada.
        """
        self.disable_buttons()
        try:
            if not self.connection:
                messagebox.showerror("Erro", "Não há conexão ativa com o servidor.")
                return
            filename = os.path.basename(filepath)
            command = f"put {filename}"
            self.connection.sendall(command.encode())
            response = self.connection.recv(1024).decode().strip()
            if response != "READY":
                messagebox.showerror("Erro", f"Servidor respondeu: {response}")
                return
            file_size = os.path.getsize(filepath)
            self.connection.sendall(str(file_size).encode())
            sent_bytes = 0
            with open(filepath, "rb") as f:
                while sent_bytes < file_size:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    self.connection.sendall(chunk)
                    sent_bytes += len(chunk)
            final_response = self.connection.recv(1024).decode()
            messagebox.showinfo("Upload", final_response)
            self.ls_command()  # Atualiza a lista de arquivos
        except Exception as e:
            messagebox.showerror("Erro", str(e))
        finally:
            self.enable_buttons()

    def put_command(self) -> None:
        """
        Inicia o upload de um arquivo único.
        """
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        threading.Thread(target=self.put_file_thread, args=(filepath,), daemon=True).start()

    def put_multiple_command(self) -> None:
        """
        Inicia o upload de múltiplos arquivos.
        """
        filepaths = filedialog.askopenfilenames()
        if not filepaths:
            return
        threading.Thread(target=self.put_multiple_files, args=(filepaths,), daemon=True).start()

    def put_multiple_files(self, filepaths: tuple) -> None:
        """
        Realiza o upload sequencial de múltiplos arquivos.
        """
        for fp in filepaths:
            self.put_file_thread(fp)

    def get_file_thread(self, filename: str) -> None:
        """
        Executa o download de um arquivo em uma thread separada.
        """
        self.disable_buttons()
        try:
            if not self.connection:
                messagebox.showerror("Erro", "Não há conexão ativa com o servidor.")
                return
            command = f"get {filename}"
            self.connection.sendall(command.encode())
            response = self.connection.recv(1024).decode().strip()
            if response.startswith("Erro"):
                messagebox.showerror("Erro", response)
                return
            try:
                file_size = int(response)
            except ValueError:
                messagebox.showerror("Erro", "Tamanho de arquivo inválido.")
                return
            self.connection.sendall("READY".encode())
            save_path = filedialog.asksaveasfilename(initialfile=filename)
            if not save_path:
                return
            received_bytes = 0
            with open(save_path, "wb") as f:
                while received_bytes < file_size:
                    chunk = self.connection.recv(4096)
                    if not chunk:
                        break
                    f.write(chunk)
                    received_bytes += len(chunk)
            messagebox.showinfo("Download", "Arquivo baixado com sucesso!")
            self.ls_command()  # Atualiza a lista de arquivos
        except Exception as e:
            messagebox.showerror("Erro", str(e))
        finally:
            self.enable_buttons()

    def get_command(self) -> None:
        """
        Inicia o download de um arquivo.
        """
        filename = simpledialog.askstring("Download", "Digite o nome do arquivo:")
        if not filename:
            return
        threading.Thread(target=self.get_file_thread, args=(filename,), daemon=True).start()

    def cd_command(self) -> None:
        """
        Muda para um diretório especificado no servidor.
        """
        folder = simpledialog.askstring("cd", "Digite o nome do diretório:")
        if not folder:
            return
        command = f"cd {folder}"
        self.connection.sendall(command.encode()) # type: ignore
        response = self.connection.recv(1024).decode() # type: ignore
        messagebox.showinfo("cd", response)
        self.ls_command()

    def cd_up_command(self) -> None:
        """
        Volta um nível no diretório atual do servidor.
        """
        command = "cd.."  # Se necessário, ajuste para "cd .." conforme o servidor
        self.connection.sendall(command.encode()) # type: ignore # type: ignore
        response = self.connection.recv(1024).decode() # type: ignore # type: ignore
        messagebox.showinfo("cd..", response)
        self.ls_command()

    def mkdir_command(self) -> None:
        """
        Cria um novo diretório no servidor.
        """
        folder = simpledialog.askstring("mkdir", "Digite o nome da nova pasta:")
        if not folder:
            return
        command = f"mkdir {folder}"
        self.connection.sendall(command.encode()) # type: ignore
        response = self.connection.recv(1024).decode() # type: ignore
        messagebox.showinfo("mkdir", response)
        self.ls_command()

    def rmdir_command(self) -> None:
        """
        Remove um diretório do servidor.
        """
        folder = simpledialog.askstring("rmdir", "Digite o nome da pasta a ser removida:")
        if not folder:
            return
        command = f"rmdir {folder}"
        self.connection.sendall(command.encode()) # type: ignore
        response = self.connection.recv(1024).decode() # type: ignore
        messagebox.showinfo("rmdir", response)
        self.ls_command()

    def logout(self) -> None:
        """
        Realiza o logout do servidor FTP e reinicia a interface.
        """
        try:
            if self.connection:
                self.connection.sendall("logout".encode())
                response = self.connection.recv(1024).decode()
                messagebox.showinfo("Logout", response)
                self.connection.close()
        except Exception as e:
            messagebox.showerror("Erro", str(e))
        finally:
            # Reinicia a interface removendo os widgets atuais
            self.container.destroy()
            self.__init__(self.master)


if __name__ == "__main__":
    root = tk.Tk()
    app = MyFTPClientGUI(root)
    root.mainloop()