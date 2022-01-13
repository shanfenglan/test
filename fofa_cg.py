import re,sys,os

class cg_e_k:
    def __init__(self,email,key,pattern,path):
        self.email = email
        self.key = key
        self.pattern = pattern
        self.path = path

    def cg(self,old,pattern,new):
        c = re.findall(pattern, old)
        old = old.replace(c[0][1], new)
        return old

    def cg_subfinder(self):
        file_data = ''
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if re.search(self.pattern, line):
                    line = "- " + self.email + ":" + self.key + "\n"
                file_data += line
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(file_data)
        print("完成" + self.path)

    def save_file(self,path):
        file_data = ''
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if re.findall(self.pattern[0], line):
                    line = self.cg(old=line,pattern=self.pattern[0], new=self.email)
                if re.findall(self.pattern[1], line):
                    line = self.cg(old=line, pattern=self.pattern[1], new=self.key)
                file_data += line
        with open(path, "w", encoding="utf-8") as f:
            f.write(file_data)

    def run(self):
        print("完成"+self.path)
        self.save_file(self.path)

if __name__ == '__main__':
    revice = ''
    try:
        revice = sys.argv[1]
    except:
        print("输出key")
        exit(0)
    key = revice
    key1 = "\"" + revice + "\""

    email="123@qq.com"
    # key = ""
    email1 = "\"123@qq.com\""
    # key1 = "\"\""
    print('''
        当前凭据为：
            {0}:{1}
            {2}:{3}
    '''.format(email,key,email1,key1)
          )

    fofa_view_path = "/Users/zhujiayu/tools/others/FofaViewer/config.properties"
    fofa_view_pattern = ['(email)=(.*)', '(key)=(.*)']

    subfinder_path = "/Users/zhujiayu/.config/subfinder/config.yaml"
    subfinder_pattern = '^- 2723382996@qq.com:'


    fofa_allin_path = "/Users/zhujiayu/tools/info_collection/asset/AlliN-main/AlliN.py"
    fofa_allin_pattern = ['(fofa_email)=(.*)', '(fofa_token)=(.*)']

    fofa_ehole_path = "/Users/zhujiayu/tools/info_collection/asset/ehole/config.ini"
    fofa_ehole_pattern = ['(Email)=(.*)', '(Fofa_token)=(.*)']


    fofa_finger_path = "/Users/zhujiayu/tools/info_collection/asset/Finger-main/config/config.py"
    fofa_finger_pattern = ['(Fofa_email)=(.*)', '(Fofa_key)=(.*)']

    fofa_vulmap_path = "/Users/zhujiayu/tools/info_collection/vulscan/vulmap/vulmap.py"
    fofa_vulmap_pattern = ['(Fofa_email)=(.*)', '(Fofa_token)=(.*)']

    fofa_oneforall_path = "/Users/zhujiayu/tools/info_collection/subdomain/OneForAll-master/config/api.py"
    fofa_oneforall_pattern = ['(fofa_api_email)=(.*)', '(fofa_api_key)=(.*)']


    fofa_oneforall = cg_e_k(email=email1,key=key1,pattern=fofa_oneforall_pattern,path=fofa_oneforall_path)
    fofa_oneforall.run()
    fofa_vulmap = cg_e_k(email=email1,key=key1,pattern=fofa_vulmap_pattern,path=fofa_vulmap_path)
    fofa_vulmap.run()
    fofa_finger = cg_e_k(email=email1,key=key1,pattern=fofa_finger_pattern,path=fofa_finger_path)
    fofa_finger.run()
    fofa_ehole = cg_e_k(email=email,key=key,pattern=fofa_ehole_pattern,path=fofa_ehole_path)
    fofa_ehole.run()
    subfiner = cg_e_k(email=email,key=key,pattern=subfinder_pattern,path=subfinder_path)
    subfiner.cg_subfinder()
    fofa_view = cg_e_k(email=email,key=key,pattern=fofa_view_pattern,path=fofa_view_path)
    fofa_view.run()
    fofa_allin = cg_e_k(email=email1,key=key1,pattern=fofa_allin_pattern,path=fofa_allin_path)
    fofa_allin.run()
