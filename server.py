#!/usr/bin/env python3
"""
Servidor FTP simples (MyFTP Server).

Este script implementa um servidor FTP que realiza operações básicas de
autenticação e manipulação de arquivos (upload, download, listagem,
navegação e gerenciamento de diretórios). Utiliza sockets para comunicação
com os clientes, bcrypt para hashing de senhas e um ThreadPoolExecutor para
concorrência.
"""

import socket
import os
import bcrypt
import logging
import concurrent.futures
import time
from pathlib import Path

# Configuração do logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Diretório base para operações de arquivo
BASE_DIR: Path = Path("server_files").resolve()
if not BASE_DIR.exists():
    BASE_DIR.mkdir(parents=True)

# Configurações de segurança da conta
MAX_FAILED_ATTEMPTS: int = 3       # Número máximo de tentativas de login falhadas permitidas
LOCKOUT_DURATION: int = 60           # Duração do bloqueio (em segundos)

# Usuários pré-hashed utilizando bcrypt
users = {
    "usuario1": bcrypt.hashpw("senha1".encode(), bcrypt.gensalt()),
    "usuario2": bcrypt.hashpw("senha2".encode(), bcrypt.gensalt()),
    "thalles": bcrypt.hashpw("1234".encode(), bcrypt.gensalt()),
    "thais": bcrypt.hashpw("1234".encode(), bcrypt.gensalt()),
    "admin": bcrypt.hashpw("admin".encode(), bcrypt.gensalt())
}

# Dicionário para rastrear tentativas de login falhadas: {username: (failed_count, lockout_until)}
failed_attempts = {}


def is_locked_out(username: str) -> bool:
    """
    Verifica se o usuário está bloqueado por múltiplas tentativas falhadas.

    :param username: Nome do usuário
    :return: True se o usuário estiver bloqueado; caso contrário, False.
    """
    if username in failed_attempts:
        _, lockout_until = failed_attempts[username]
        if time.time() < lockout_until:
            return True
    return False


def record_failed_attempt(username: str) -> None:
    """
    Registra uma tentativa de login falhada e bloqueia a conta, se necessário.

    :param username: Nome do usuário que teve a tentativa falhada.
    :return: None
    """
    current_time = time.time()
    count = failed_attempts.get(username, (0, current_time))[0] + 1
    if count >= MAX_FAILED_ATTEMPTS:
        lockout_until = current_time + LOCKOUT_DURATION
        logging.warning(f"Usuário {username} bloqueado até {lockout_until}")
        failed_attempts[username] = (count, lockout_until)
    else:
        failed_attempts[username] = (count, current_time)


def reset_failed_attempts(username: str) -> None:
    """
    Reseta o contador de tentativas de login falhadas para um usuário.

    :param username: Nome do usuário.
    :return: None
    """
    if username in failed_attempts:
        del failed_attempts[username]


def safe_path(current_dir: Path, target: str) -> Path:
    """
    Realiza a junção segura de um caminho relativo com o diretório atual,
    garantindo que o caminho resultante permaneça dentro do BASE_DIR.

    :param current_dir: Diretório atual.
    :param target: Caminho ou nome do diretório/arquivo alvo.
    :return: Novo caminho resolvido se for válido; caso contrário, retorna o diretório atual.
    """
    new_path = (current_dir / target).resolve()
    if BASE_DIR in new_path.parents or new_path == BASE_DIR:
        return new_path
    return current_dir


def client_handler(conn: socket.socket, addr) -> None:
    """
    Gerencia a conexão com um cliente: realiza autenticação, processa comandos
    e executa operações de arquivo.

    Comandos suportados:
      - login <usuario> <senha>
      - put <nome_arquivo>
      - get <nome_arquivo>
      - ls
      - cd <nome_da_pasta>
      - cd..
      - mkdir <nome_da_pasta>
      - rmdir <nome_da_pasta>
      - logout

    :param conn: Socket da conexão com o cliente.
    :param addr: Endereço do cliente.
    :return: None
    """
    logging.info(f"Conexão estabelecida com {addr}")
    current_dir = BASE_DIR
    authenticated = False
    username = None

    # Define timeout para conexões inativas (300 segundos)
    conn.settimeout(300)

    try:
        while True:
            data = conn.recv(1024).decode().strip()
            if not data:
                break
            logging.info(f"Recebido de {addr}: {data}")
            parts = data.split()

            # Comando: login
            if parts[0] == "login":
                if len(parts) != 3:
                    conn.sendall("Erro: Comando login inválido. Use: login <usuario> <senha>\n".encode())
                    continue
                _, user, password = parts
                if is_locked_out(user):
                    conn.sendall("Erro: Conta bloqueada devido a múltiplas tentativas falhadas.\n".encode())
                    continue
                if user in users and bcrypt.checkpw(password.encode(), users[user]):
                    authenticated = True
                    username = user
                    reset_failed_attempts(user)
                    conn.sendall("Login bem-sucedido!\n".encode())
                else:
                    record_failed_attempt(user)
                    conn.sendall("Erro: Usuário ou senha incorretos.\n".encode())

            # Exige autenticação para os comandos subsequentes
            elif not authenticated:
                conn.sendall("Erro: Você deve fazer login primeiro.\n".encode())

            # Comando: put (upload de arquivo)
            elif parts[0] == "put":
                if len(parts) != 2:
                    conn.sendall("Erro: Comando put inválido. Use: put <nome_arquivo>\n".encode())
                    continue
                filename = parts[1]
                safe_file_path = (current_dir / filename).resolve()
                # Verifica se o caminho está dentro do BASE_DIR
                if BASE_DIR not in safe_file_path.parents and safe_file_path != BASE_DIR:
                    conn.sendall("Erro: Caminho de arquivo inválido.\n".encode())
                    continue
                conn.sendall("READY".encode())
                file_size_str = conn.recv(1024).decode().strip()
                try:
                    file_size = int(file_size_str)
                except ValueError:
                    conn.sendall("Erro: Tamanho de arquivo inválido.\n".encode())
                    continue
                received_bytes = 0
                with open(safe_file_path, "wb") as f:
                    while received_bytes < file_size:
                        # Recebendo chunks de dados sem tentar decodificá-los
                        chunk = conn.recv(min(4096, file_size - received_bytes))
                        if not chunk:
                            break
                        f.write(chunk)
                        received_bytes += len(chunk)
                if received_bytes == file_size:
                    conn.sendall("Arquivo recebido com sucesso.\n".encode())
                else:
                    conn.sendall("Erro: Transferência incompleta.\n".encode())

            # Comando: get (download de arquivo)
            elif parts[0] == "get":
                if len(parts) != 2:
                    conn.sendall("Erro: Comando get inválido. Use: get <nome_arquivo>\n".encode())
                    continue
                filename = parts[1]
                safe_file_path = (current_dir / filename).resolve()
                if not (safe_file_path.exists() and (BASE_DIR in safe_file_path.parents or safe_file_path == BASE_DIR)):
                    conn.sendall("Erro: Arquivo não encontrado.\n".encode())
                    continue
                file_size = os.path.getsize(safe_file_path)
                conn.sendall(str(file_size).encode())
                ack = conn.recv(1024).decode().strip()
                if ack != "READY":
                    continue
                with open(safe_file_path, "rb") as f:
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        conn.sendall(chunk)
                conn.sendall("Transferência concluída.\n".encode())

            # Comando: ls (listar conteúdo do diretório)
            elif parts[0] == "ls":
                try:
                    items = os.listdir(current_dir)
                    if not items:
                        conn.sendall("Diretório vazio.".encode())
                    else:
                        lines = []
                        for item in items:
                            full_path = current_dir / item
                            if full_path.is_dir():
                                lines.append(f"{item}:Dir:-")
                            else:
                                size = os.path.getsize(full_path)
                                lines.append(f"{item}:File:{size}")
                        response = "\n".join(lines)
                        conn.sendall(response.encode())
                except Exception as e:
                    conn.sendall(f"Erro ao listar diretório: {str(e)}".encode())

            # Comando: cd (mudar de diretório)
            elif parts[0] == "cd":
                if len(parts) < 2:
                    conn.sendall("Erro: Comando cd inválido. Use: cd <nome_da_pasta>\n".encode())
                    continue
                folder = " ".join(parts[1:])
                new_path = safe_path(current_dir, folder)
                if new_path.exists() and new_path.is_dir():
                    current_dir = new_path
                    conn.sendall(f"Diretório alterado para {str(current_dir)}\n".encode())
                else:
                    conn.sendall("Erro: Diretório não encontrado.\n".encode())

            # Comando: cd.. (voltar um nível no diretório)
            elif data == "cd..":
                parent = current_dir.parent
                if BASE_DIR in parent.parents or parent == BASE_DIR:
                    current_dir = parent
                    conn.sendall(f"Diretório alterado para {str(current_dir)}\n".encode())
                else:
                    conn.sendall("Erro: Já está no diretório raiz.\n".encode())

            # Comando: mkdir (criar diretório)
            elif parts[0] == "mkdir":
                if len(parts) != 2:
                    conn.sendall("Erro: Comando mkdir inválido. Use: mkdir <nome_da_pasta>\n".encode())
                    continue
                folder = parts[1]
                new_dir = (current_dir / folder).resolve()
                if BASE_DIR not in new_dir.parents and new_dir != BASE_DIR:
                    conn.sendall("Erro: Caminho inválido.\n".encode())
                    continue
                try:
                    os.mkdir(new_dir)
                    conn.sendall("Diretório criado com sucesso.\n".encode())
                except Exception as e:
                    conn.sendall(f"Erro ao criar diretório: {str(e)}\n".encode())

            # Comando: rmdir (remover diretório)
            elif parts[0] == "rmdir":
                if len(parts) != 2:
                    conn.sendall("Erro: Comando rmdir inválido. Use: rmdir <nome_da_pasta>\n".encode())
                    continue
                folder = parts[1]
                dir_path = (current_dir / folder).resolve()
                # Verificação de segurança: garantir que o caminho está dentro de BASE_DIR
                if BASE_DIR not in dir_path.parents and dir_path != BASE_DIR:
                    conn.sendall("Erro: Caminho inválido.\n".encode())
                    continue
                if dir_path.exists() and dir_path.is_dir():
                    try:
                        os.rmdir(dir_path)
                        conn.sendall("Diretório removido com sucesso.\n".encode())
                    except OSError as e:
                        if "Directory not empty" in str(e) or "directory not empty" in str(e):
                            conn.sendall("Erro: O diretório não está vazio. Remova todos os arquivos e subdiretórios primeiro.\n".encode())
                        else:
                            conn.sendall(f"Erro ao remover diretório: {str(e)}\n".encode())
                    except Exception as e:
                        conn.sendall(f"Erro ao remover diretório: {str(e)}\n".encode())
                else:
                    conn.sendall("Erro: Diretório não encontrado.\n".encode())

            # Comando: logout (encerrar conexão)
            elif parts[0] == "logout":
                conn.sendall("Logout realizado.\n".encode())
                break

            # Comando não reconhecido
            else:
                conn.sendall("Comando não reconhecido.\n".encode())

    except socket.timeout:
        logging.warning(f"Conexão com {addr} expirou por timeout.")
    except Exception as e:
        logging.error(f"Erro com {addr}: {e}")
    finally:
        conn.close()
        logging.info(f"Conexão encerrada com {addr}")


def start_server(host: str = "0.0.0.0", port: int = 2121) -> None:
    """
    Inicializa o servidor MyFTP no host e porta especificados.

    Cria um socket, configura opções, associa ao endereço e porta, e inicia a
    escuta de conexões. Utiliza ThreadPoolExecutor para tratar múltiplos clientes
    de forma concorrente.

    :param host: Endereço do host (padrão "0.0.0.0" para escutar em todas as interfaces).
    :param port: Porta para escuta (padrão 2121).
    :return: None
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Permite a reutilização do endereço
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    server_socket.settimeout(10)
    logging.info(f"Servidor MyFTP rodando em {host}:{port}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        while True:
            try:
                client_sock, addr = server_socket.accept()
                executor.submit(client_handler, client_sock, addr)
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"Erro no servidor: {e}")


if __name__ == "__main__":
    start_server()