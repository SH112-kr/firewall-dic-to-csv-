import os
import pymysql
import re
import time  
import datetime 
import ipaddress
import macaddress
import pandas as pd


os.chdir("D:\\")
data1 = ''
if __name__ == "__main__":
    print("PROGRAM START", datetime.datetime.now())
    with open('testlog.txt','r') as f:
        print("읽기 시작", datetime.datetime.now())
        while 1:
            data = f.read(100000000)
            data1 = data1 + data
            if not data:
                break

    
    
    f.close()
    print("읽기 끝", datetime.datetime.now())
    data1 = data1.replace("BOB_FORENSICS",'').replace("ETH0",'').replace('FIREWALL05783','')
    data1 = data1.replace("   "," ").replace("  "," ")

    regx = re.compile('((?:(\w{3}) (\w{3}) (\d{1,2}) (\d{2}:\d{2}:\d{2}) (\d{4})) ((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})) ((?:(?:[0-9a-fA-F]{2}):){5}[0-9a-fA-F]{2}) (\d*) ((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})) ((?:(?:[0-9a-fA-F]{2}):){5}[0-9a-fA-F]{2}) (\d*) (\d*))')
    result = regx.findall(data1)
    print('정규식 파싱  끝', datetime.datetime.now())
        #1 Mon
        #2 Oct
        #3 1
        #4 00:46:40
        #5 2018
        #6 source ip
        #7 source mac
        #8 source port
        #9 dest ip
        #10 dest mac
        #11 dest port
        #12 file size
    epoch=[]
    day=[]
    source_IP=[]
    source_Mac=[]
    source_Port=[]
    Dest_IP=[]
    Dest_Mac=[]
    Dest_Port=[]
    file_size=[]
    for row in result:
        row = list(row)
        row[2] = row[2].replace('Jan','1').replace('Feb','2').replace('Mar','3').replace('Apr','4').replace('May','5').replace('Jun','6').replace('Jul','7').replace('Aug','8').replace('Sep','9').replace('Oct','10').replace('Nov','11').replace('Dec','12')
        #date = str(row[5], row[2], row[3])
        pymysql.TIMESTAMP = (row[5]+'-'+row[2]+'-'+row[3] + " " + row[4])  
        pattern = "%Y-%m-%d %H:%M:%S"

        
        strp = (time.strptime(pymysql.TIMESTAMP, pattern))
        epoch.append(datetime.datetime(strp[0], strp[1], strp[2], strp[3], strp[4], strp[5]) + datetime.timedelta(hours=9)) #UTC +9
        source_IP.append(int(ipaddress.ip_address(row[6])))
        source_Mac.append(int(macaddress.MAC(row[7])))
        source_Port.append(int(row[8]))
        day.append(str(row[1]))
        Dest_IP.append(int(ipaddress.ip_address(row[9])))
        Dest_Mac.append(int(macaddress.MAC(row[10])))
        Dest_Port.append(int(row[11]))
        file_size.append(int(row[12]))

    df_temp = pd.DataFrame({'timestamp' : epoch ,'day' : day, 'source_IP' : source_IP, 'source_Mac' : source_Mac, 'source_Port': source_Port, 'Dest_IP' : Dest_IP, 'Dest_Mac' : Dest_Mac, 'Dest_Port' : Dest_Port,'file_size' : file_size })
    df_temp.to_csv('firewall.csv')
    print("Success!")
    
