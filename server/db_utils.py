import datetime


def create_tables(db_connection):
    db_connection.execute('create table if not exists client\
     (ID char(16) primary key not NULL, Name varchar(255) not NULL,\
     PublicKey varchar(160), LastSeen datetime, AESKey char(16));')
    db_connection.execute('create table if not exists files\
     (ID char(16) primary key not NULL, FileName varchar(255) not NULL,\
     PathName varchar(255), Verified boolean);')


def is_exist_client(db_connection, client_name):
    cursor = db_connection.execute('select * from client where Name=?', (client_name,))
    data = cursor.fetchall()
    if len(data) == 0:
        return False
    else:
        return True


def get_client(db_connection, client_name):
    cursor = db_connection.execute('select * from client where Name=?', (client_name,))
    data = cursor.fetchall()
    return data[0][0], data[0][1], data[0][2], data[0][3], str(data[0][4])


def add_client(db_connection, client_id, name, public_key, aes_key):
    db_connection.execute('insert into client(ID,Name,PublicKey,LastSeen,AESKey) values(?,?,?,?,?)',
                          (client_id, name, public_key, datetime.datetime.now(), aes_key))
    db_connection.commit()


def update_client(db_connection, client_id, name, public_key, aes_key):
    db_connection.execute('update client set Name=?, PublicKey=?, LastSeen=?, AESKey=? where ID=?',
                          (name, public_key, datetime.datetime.now(), aes_key, client_id))
    db_connection.commit()


def add_file(db_connection, file_id, file_name, file_path, verified):
    db_connection.execute('insert into files(ID,FileName,PathName,Verified) VALUES(?,?,?,?)',
                          (file_id, file_name, file_path, verified))
    db_connection.commit()


def update_file(db_connection, file_id, file_name, path_name, verified):
    db_connection.execute('update files set FileName=?, PathName=?, Verified=? where ID=?',
                          (file_name, path_name, verified, file_id))
    db_connection.commit()
