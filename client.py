# клиент
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from cryptography.fernet import Fernet
import base64


class DFH:
    def exchange(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(('localhost', 9091))
        self.parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
        self.dh_numbers = self.parameters.parameter_numbers()
        # передаем выбранные P и G на сервер
        self.sock.send(str(self.dh_numbers.p).encode('utf-8'))
        self.sock.send(str(self.dh_numbers.g).encode('utf-8'))

        # альтарнативный вариант - задать P и G вручную
        # p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        # g = 2
        #
        # params_numbers = dh.DHParameterNumbers(p,g)
        # parameters = params_numbers.parameters(default_backend())

        # Получим закрытый и открытый ключ
        self.client_private_key = self.parameters.generate_private_key()
        self.client_public_key  = self.client_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # print("Открытый ключ клиента: "+ self.client_public_key.hex())
        # принятие публичного ключа сервер
        length = self.sock.recv(2)                               # длина сообщения
        self.server_public_key = self.sock.recv(int.from_bytes(length, "big"))
        # print("Получил откртый ключ сервера: " + str(self.server_public_key.hex()))       # получили публичный ключ сервера
        self.server_public_key_1 = load_der_public_key(self.server_public_key, default_backend())

        # Отправка публичного ключа
        self.sock.send(len(self.client_public_key).to_bytes(2, "big") + self.client_public_key)

        # Общий ключ
        hkdf_obj1 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"",
        )
        hkdf_obj2 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"",
        )
        hkdf_obj3 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"",
        )
        self.client_public_key_hash=hkdf_obj1.derive(self.client_public_key)
        self.server_public_key_hash=hkdf_obj2.derive(self.server_public_key)

        # print("Генерация общего ключа...")
        self.shared_key = hkdf_obj3.derive(self.client_private_key.exchange(self.server_public_key_1))
        # print("Наш общий ключ!: " + str(self.shared_key.hex()))

        # return self.shared_key

    def ciper(self, mess):
        key = base64.urlsafe_b64encode(self.shared_key)

        self.sock.send(str(mess).encode('utf-8'))
        # self.sock.send(str(input('Напиши сообщение для кодировки: ')).encode('utf-8'))
        self.enc_mess = self.sock.recv(2048).decode('UTF-8')
        print('Получил шифр:', self.enc_mess)

        fernet = Fernet(key)
        self.dectex = fernet.decrypt(bytes(self.enc_mess, 'utf-8')).decode()
        print('Расшифровал:', self.dectex)

    def close_conn(self):
        self.sock.close()

if __name__ == '__main__':
    first = DFH()
    first.exchange()
    first.ciper(input("Введи текст"))
    first.close_conn()
