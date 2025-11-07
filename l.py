from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, base64

def encrypt_message_gcm(msg, key_bytes):
    if len(msg) > 128:
        raise ValueError("A mensagem não pode exceder 128 caracteres!")

    data = msg.encode("utf-8")
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    return base64.b64encode(nonce + tag + ciphertext).decode("utf-8")

def decrypt_message_gcm(encoded_data, key_bytes):

    raw = base64.b64decode(encoded_data)
    nonce = raw[:12]
    tag = raw[12:28]
    ciphertext = raw[28:]

    cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()

    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted.decode("utf-8")

def main():
    print("=" * 50)
    print(" SISTEMA DE CRIPTOGRAFIA AES-GCM")
    print("=" * 50)

    senha_master = input("\nDigite a senha de acesso: ")

    if senha_master != "criptografia-2025":
        print("\n Acesso negado! Você não tem permissão para usar este sistema.")
        return
    else:
        print("\n Acesso permitido! Sistema iniciado.\n")

    while True:
        print("-" * 50)
        acao = input("Escolha: (C) Criptografar | (D) Descriptografar | (S) Sair: ").strip().upper()

        if acao == "C":
            msg = input("\nDigite a mensagem para criptografar (máx 128 caracteres): ")
            try:
                key_bytes = os.urandom(16)
                chave_base64 = base64.b64encode(key_bytes).decode("utf-8")
                cifrada = encrypt_message_gcm(msg, key_bytes)

                print("\n Mensagem criptografada (Base64, Nonce+Tag+CT):")
                print(cifrada)
                print("\n Chave (guarde para descriptografar):")
                print(chave_base64)
                print("-" * 50)

            except Exception as e:
                print("\n⚠ Erro ao criptografar:", str(e))

        elif acao == "D":
            ct_base64 = input("\nDigite a mensagem criptografada (Base64, Nonce+Tag+CT): ")
            chave_base64 = input("Digite a chave (Base64): ")

            try:
                key_bytes = base64.b64decode(chave_base64)
                decifrada = decrypt_message_gcm(ct_base64, key_bytes)
                print("\n Mensagem decifrada:")
                print(decifrada)
                print("-" * 50)

            except Exception:
                print("\n Erro: chave incorreta ou mensagem alterada.")
                print("-" * 50)

        elif acao == "S":
            print("\n Encerrando o sistema. Até logo!")
            break

        else:
            print("\n Opção inválida. Digite C, D ou S.")
            print("-" * 50)

if __name__ == "__main__":
    main()