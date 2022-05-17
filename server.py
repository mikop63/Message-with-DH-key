# сервер
# <3 спасибо: https://stackoverflow.com/questions/57286946/python-diffie-hellman-exchange-cryptography-library-shared-key-not-the-same
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from cryptography.fernet import Fernet
import base64

try:
    newsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                            # AF_INET - для ip4 SOCK_DGRAM - для UDP
    newsocket.bind(('', 9091))           # хост пустой (доуступн для всех интерфейсов) и порт 9090
    newsocket.listen(5)                  # сервер в режиме приема соединений
    print('[*]Сервер запущен, ожидает подключения...')
    while True:

        client, addr = newsocket.accept()    # принимаем подключение. accept-возвращает кортеж с двумя элементами: новый сокет и адрес клиента.
        print("[*]Принято соединение от: %a:%d" % (addr[0],addr[1]))

        # генерировать P и G еще раз нельзя
        # parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

        # вариант - задавать их в ручную (быстро и удобно при разработке)
        # p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        # g = 2

        # получение P и G от клиента
        p = int(client.recv(2048).decode('UTF-8'))
        g = int(client.recv(2048).decode('UTF-8'))
        params_numbers = dh.DHParameterNumbers(p,g)
        parameters = params_numbers.parameters(default_backend())


        # Получим закрытый и открытый ключ
        server_private_key   = parameters.generate_private_key()
        server_public_key    = server_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # отправка публичного ключа сервера -> клиенту
        client.send(len(server_public_key).to_bytes(2, "big") + server_public_key)
        print("Отправка публичного ключа сервера: " + str(server_public_key.hex()))

        # принятие публичного ключа клиента
        length            = client.recv(2)
        client_public_key = client.recv(int.from_bytes(length, "big"))
        client_public_key = load_der_public_key(client_public_key, default_backend())

        # Общий ключ
        hkdf_obj = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"",
        )
        shared_key = hkdf_obj.derive(server_private_key.exchange(client_public_key))
        print("Наш общий ключ: " + str(shared_key.hex()))

# --------------------------------------------Обмен ключами завершен----------------------------------------------------

        str1 = client.recv(2048).decode('UTF-8')
        key = base64.urlsafe_b64encode(shared_key)
        print("Ключ для шифрования сообщения:", key)


        fernet = Fernet(key)
        enctex = fernet.encrypt(str1.encode())
        dectex = fernet.decrypt(enctex).decode()
        print("Первоначальное сообщение: ", str1)
        print("Зашифрованное сообщение: ", enctex)
        print("Расшифврованное сообщение: ", dectex)

        client.send(str(enctex.decode("utf-8")).encode('utf-8'))



        client.shutdown(socket.SHUT_WR)

except KeyboardInterrupt:                                                                             # первать работу сервара Control+C или Delete
    socket.close()
    print(' [*]Выключение...')
