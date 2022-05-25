from tkinter import *
from tkinter import ttk
from functools import partial
import client

class Wind(client.DFH):
    def form_accept(self):
        '''
        Отправка сообщения, принятие зашифвроанного сообщения, расшифровка с помощью своего ключа
        '''
        first.ciper(self.ent4.get())

        self.Lab1 = Label(self.root, text= 'Отправил шифр на сервер:', font="Arial 10")
        self.Lab1.grid(row = 5, column = 0, columnspan=1, sticky=W, padx=(10,0), pady=(3,3))

        self.ent5 = Entry(self.root,width=110,bd=3)
        self.ent5.grid(row=5, column=1, columnspan=3, sticky=W, padx=(4,0), pady=(3,3))
        self.ent5.insert(0,first.enctext)

        self.Lab2 = Label(self.root, text= 'Получил расшифровку от сервера на проверку:', font="Arial 10")
        self.Lab2.grid(row = 6, column = 0, columnspan=1, sticky=W, padx=(10,0), pady=(3,3))

        self.ent6 = Entry(self.root,width=110,bd=3)
        self.ent6.grid(row=6, column=1, columnspan=3, sticky=W, padx=(4,0), pady=(3,3))
        self.ent6.insert(0,first.decr_mess)


    def form_send(self):
        '''
        Создание формы для отправки сообщения после обмена ключами
        :return:
        '''
        self.Lab = Label(self.root, text= 'Введи текст\nдля передачи:', font="Arial 12")
        self.Lab.grid(row = 4, column = 0, columnspan=1, sticky=W, padx=(10,0), pady=(3,3))

        self.ent4 = Entry(self.root,width=87,bd=3)
        self.ent4.grid(row=4, column=1, columnspan=3, sticky=W, padx=(4,0), pady=(3,3))

        self.but2 = Button(self.root, text= 'Отправить\nсообщение', width=10, height=3, bg='white', fg='black', command=self.form_accept)
        self.but2.grid(row = 4, column = 3,sticky=E, padx=(0,0), pady=(3,3))

        self.but3 = Button(self.root, text= 'Разрыв соединения', bg='red', fg='black', command=self.disconnect)
        self.but3.grid(row = 0, column = 3, sticky=N+E, padx=(0,10), pady=(3,3))


    def connect(self):
        '''
        создает подключение, выводит общий ключ.
        :return:
        '''
        first.exchange()
        self.ent1.delete(0,END)
        self.ent2.delete(0,END)
        self.ent3.delete(0,END)
        self.ent1.config(state='normal')
        self.ent2.config(state='normal')
        self.ent3.config(state='normal')
        self.ent1.insert(0,first.client_public_key_hash.hex())              # Открытый ключ клиента
        self.ent2.insert(0,first.server_public_key_hash.hex())              # Открытый ключ сервера
        self.ent3.insert(0,first.shared_key.hex())                          # Общий ключ
        # self.ent1.config(state='disabled')
        # self.ent2.config(state='disabled')
        # self.ent3.config(state='disabled')
        Wind.form_send(self)

    def disconnect(self):
        '''
        Разрывает соединение, удаляет созданные виджеты
        :return:
        '''
        first.close_conn()
        first.sock.close()
        # очищение полей с ключами
        self.ent1.delete(0,END)
        self.ent2.delete(0,END)
        self.ent3.delete(0,END)
        self.ent1.config(state='disabled')
        self.ent2.config(state='disabled')
        self.ent3.config(state='disabled')
        # удаление кнопки удаления
        self.but2.grid_remove()
        # удаление виджитов отправки
        self.Lab .grid_remove()
        self.ent4.grid_remove()
        self.but3.grid_remove()
        # удаление виджетов принятия

    def __init__(self):
        self.root = root
        self.root.title('Основноя программа')

        # создание надписи
        Label(self.root, text= 'Лабораторная работа 5', font="Arial 24").grid(row = 0, column = 0, columnspan=4, padx=(0,0), pady=(3,20))

        self.but = Button(self.root, text= 'Обменяться\nключами', width=10, height=5, bg='white', fg='black', command=self.connect).grid(row = 1, column = 0, rowspan=3, padx=(0,10), pady=(3,3))

        Label(self.root, text= 'Открытый ключ клиента:', font="Arial 12").grid(row = 1, column = 1, columnspan=1, sticky=E, padx=(0,3), pady=(3,3))
        Label(self.root, text= 'Открытый ключ сервера:', font="Arial 12").grid(row = 2, column = 1, columnspan=1, sticky=E, padx=(0,3), pady=(3,3))
        Label(self.root, text= 'Общий ключ:', font="Arial 12")           .grid(row = 3, column = 1, columnspan=1, sticky=E, padx=(0,3), pady=(3,3))
        self.ent1 = Entry(self.root,width=70,bd=3, state='disabled')
        self.ent2 = Entry(self.root,width=70,bd=3, state='disabled')
        self.ent3 = Entry(self.root,width=70,bd=3, state='disabled')
        self.ent1.grid(row=1, column=2, columnspan=2, padx=(0,0), pady=(3,3))
        self.ent2.grid(row=2, column=2, columnspan=2, padx=(0,0), pady=(3,3))
        self.ent3.grid(row=3, column=2, columnspan=2, padx=(0,0), pady=(3,3))


if __name__ == '__main__':
    root = Tk()
    root.title("Основное окно")
    first = client.DFH()
    obj = Wind()
    root.mainloop()



