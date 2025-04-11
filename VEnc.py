from os.path import exists,dirname,getsize,join
from functools import lru_cache
from random import randint,choices
from string import ascii_letters
from secrets import token_bytes
from os import rename,remove
__author__="Vahab Programmer https://Github.com/Vahab-Programmer"
__version__="0.0.1"
class VEncrypter:
    def __init__(self,key:bytes,salt:bytes=token_bytes(32)):
        assert len(salt)==32
        assert isinstance(salt,bytes)
        self.__orgkey=key
        self.__orgsalt=salt
        self.__salt=self.__make_key(salt)
        self.__key=self.__make_key(key+self.__salt)
    def update_salt(self,salt:bytes=None)->None:
        if not salt:salt=token_bytes(32)
        assert isinstance(salt,bytes)
        assert len(salt)==32
        self.__orgsalt=salt
        self.__salt=self.__make_key(self.__orgsalt)
        self.__key=self.__make_key(self.__orgkey+self.__salt)
    @lru_cache(32)
    def __make_key(self,key:bytes)->bytes:
        __key=bytes()
        for index, data in enumerate(key):
            __key += ((data + key[index - 1] if index != 1 else key[-1] +256+index) % 256).to_bytes()
        return __key
    @staticmethod
    def __make_name(filepath:str)->str:return join(dirname(filepath),"".join(choices(ascii_letters,k=randint(1,64)))+".tmp")
    def get_key(self)->dict:return {"key":self.__orgkey,"salt":self.__orgsalt}
    def encrypt(self,data:bytes)->bytes:
        res=bytes()
        if not data: return data
        for i,sd in enumerate(data):
            res += (((sd^self.__key[i%len(self.__key)])+256+i+(res[-1 if i == 0 else i-1] if len(res)>0 else 0))%256).to_bytes()
        res.replace(res[0].to_bytes(),((res[0]+res[-1])%256).to_bytes())
        return res
    def decrypt(self,data:bytes)->bytes:
        res = bytes()
        if not data:return data
        ((data[0]-data[-1])%256).to_bytes()
        for i, sd in enumerate(data):
            res+=(((sd+256-i-(data[-1 if i == 0 else i-1] if len(res)>0 else 0))^self.__key[i%len(self.__key)])%256).to_bytes()
        return res
    def encrypt_file(self,filepath,asu:bool=True) -> bool:
        if not exists(filepath):return False
        if getsize(filepath)==0:return False
        source=open(filepath,"rb")
        dstname=self.__make_name(filepath)
        destination=open(dstname,"wb")
        destination.write(self.__salt)
        repeat=getsize(filepath)//len(self.__key)
        if not (getsize(filepath)%len(self.__key))==0:repeat+=1
        for _ in range(repeat):
            data=source.read(len(self.__key))
            destination.write(self.encrypt(data))
        destination.flush()
        destination.close()
        source.close()
        remove(filepath)
        rename(dstname,filepath)
        if asu:self.update_salt()
        return True
    def decrypt_file(self, filepath) -> bool:
        if not exists(filepath):return False
        source=open(filepath,"rb")
        self.__key=self.__make_key(self.__orgkey+source.read(32))
        dstname=self.__make_name(filepath)
        destination=open(dstname,"wb")
        repeat=getsize(filepath)//len(self.__key)
        if not (getsize(filepath)%len(self.__key))==0: repeat+= 1
        for _ in range(repeat):
            data=source.read(len(self.__key))
            destination.write(self.decrypt(data))
        destination.flush()
        destination.close()
        source.close()
        remove(filepath)
        rename(dstname,filepath)
        self.__key=self.__make_key(self.__orgkey+self.__salt)
        return True
