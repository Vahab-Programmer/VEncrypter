from os.path import exists,dirname,getsize,join
from functools import lru_cache
from random import randint,choices
from string import ascii_letters
from secrets import token_bytes
from os import rename,remove
class VEncrypter:
    def __init__(self,key:bytes,salt:bytes=token_bytes(32)):
        assert len(salt)==32
        assert isinstance(salt,bytes)
        self.__orgkey=key
        self.__salt=salt
        self.__key=self.__make_key(key,self.__salt)
    @lru_cache(32)
    def __make_key(self,key:bytes,salt:bytes)->bytes:
        __key=bytes()
        for index, data in enumerate(key):
            __key += ((data + key[index - 1] if index != 1 else key[-1] + 256) % 256).to_bytes()
        return __key+salt
    @staticmethod
    def __make_name(filepath:str)->str:return join(dirname(filepath),"".join(choices(ascii_letters,k=randint(1,64)))+".tmp")
    def get_key(self)->dict:return {"key":self.__key,"salt":self.__salt}
    def encrypt(self,data:bytes)->bytes:
        res=bytes()
        for i,sd in enumerate(data):
            res += ((sd+self.__key[i%len(self.__key)]+256+i)%256).to_bytes()
        return res
    def decrypt(self,data:bytes)->bytes:
        res = bytes()
        for i, sd in enumerate(data):
            res += ((sd-self.__key[i%len(self.__key)]+256-i)%256).to_bytes()
        return res
    def encrypt_file(self,filepath)->bool:
        if not exists(filepath):return False
        source=open(filepath,"rb")
        dstname=self.__make_name(filepath)
        destination=open(dstname,"wb")
        destination.write(self.__salt)
        repeat=getsize(filepath)//1048576
        if not (getsize(filepath)%1048576)==0:repeat+=1
        for _ in range(repeat):
            data=source.read(1048576)
            destination.write(self.encrypt(data))
        destination.flush()
        destination.close()
        source.close()
        remove(filepath)
        rename(dstname,filepath)
        return True
    def decrypt_file(self,filepath)->bool:
        if not exists(filepath): return False
        source = open(filepath, "rb")
        self.__key=self.__make_key(self.__orgkey,source.read(32))
        dstname = self.__make_name(filepath)
        destination = open(dstname, "wb")
        repeat = getsize(filepath) // 1048576
        if not (getsize(filepath)%1048576)==0: repeat += 1
        for _ in range(repeat):
            data = source.read(1048576)
            destination.write(self.decrypt(data))
        destination.flush()
        destination.close()
        source.close()
        remove(filepath)
        rename(dstname, filepath)
        self.__key=self.__make_key(self.__orgkey,self.__salt)
        return True