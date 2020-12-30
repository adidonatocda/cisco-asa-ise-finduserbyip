import random
import sys
import string
import requests
import urllib3
from pprint import pprint
import json
import getpass
import xml.etree.ElementTree as ET
from ipwhois import IPWhois
from ipwhois.utils import get_countries
from ipwhois import __version__

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

asa_headers = {'Content-Type': 'application/json', 'User-Agent':'REST API Agent'}
ise_headers = {'Content-Type': 'application/xml', 'User-Agent':'REST API Agent'}
asa_uri = "/api/monitoring/connections"
ise_uri = "/admin/API/mnt/Session/ActiveList"
asa_host="172.16.122.10"
ise_host="172.16.122.250"
asaurl="https://"+asa_host+asa_uri
print(asaurl)
iseurl="https://"+ise_host+ise_uri
print(iseurl)
asa_user=input("ASA Username: ")
ise_user=input("ISE Username: ")

try:
    asa_pwd=getpass.getpass(prompt='ASA Password: ', stream=None)
    ise_pwd=getpass.getpass(prompt='ISE Password: ', stream=None)
except Exception as error:
    print ('ERROR',error)

asareq=requests.get(asaurl,auth=(asa_user, asa_pwd),headers=asa_headers,verify=False)
print(asareq)
print("==================")
print(asareq.text)
print("==================")
isereq=requests.get(iseurl,auth=(ise_user, ise_pwd),headers=ise_headers,verify=False)
print(isereq)
print("==================")
print(isereq.text)
print("==================")


#Sample JSON from ASA Rest API for testing
asa_json=r"""{
  "kind": "collection#ConnectionDetails",
  "selfLink": "https://192.168.0.102/api/monitoring/connections",
  "rangeInfo": {
    "offset": 0,
    "limit": 1,
    "total": 3
  },
  "items": [
    {
      "protocol": "TCP",
      "sourceSecurityTag": "",
      "sourceIp": "192.168.0.60",
      "sourcePort": "9338",
      "destinationSecurityTag": "",
      "destinationIp": "192.168.0.102",
      "destinationPort": "443",
      "duration": "0:00:00",
      "bytesSent": "0 KB"
    },
    {
      "protocol": "TCP",
      "sourceSecurityTag": "",
      "sourceIp": "192.168.0.61",
      "sourcePort": "9438",
      "destinationSecurityTag": "",
      "destinationIp": "192.168.0.102",
      "destinationPort": "443",
      "duration": "0:00:00",
      "bytesSent": "0 KB"
    },
    {
      "protocol": "TCP",
      "sourceSecurityTag": "",
      "sourceIp": "192.168.0.62",
      "sourcePort": "9538",
      "destinationSecurityTag": "",
      "destinationIp": "192.168.0.102",
      "destinationPort": "443",
      "duration": "0:00:00",
      "bytesSent": "0 KB"
    }
  ]
}"""

#Sample JSON from ISE Rest API for testing
ise_xml="""
<activeList noOfActiveSession="3">
	<activeSession>
		<user_name>test_user1</user_name>
		<calling_station_id>50:00:00:01:00:00</calling_station_id>
		<nas_ip_address>192.168.0.60</nas_ip_address>
		<acct_session_id>00000001</acct_session_id>
		<audit_session_id>0A00640100000011000DE3E9</audit_session_id>
		<server>ISE</server>
		<framed_ip_address>10.0.10.20</framed_ip_address>
		<framed_ipv6_address/>
	</activeSession>
		<activeSession>
		<user_name>test_user2</user_name>
		<calling_station_id>50:00:00:02:00:00</calling_station_id>
		<nas_ip_address>192.168.0.61</nas_ip_address>
		<acct_session_id>00000002</acct_session_id>
		<audit_session_id>0A00640100000011000DE3E8</audit_session_id>
		<server>ISE</server>
		<framed_ip_address>10.0.10.20</framed_ip_address>
		<framed_ipv6_address/>
	</activeSession>
		<activeSession>
		<user_name>test_user3</user_name>
		<calling_station_id>50:00:00:03:00:00</calling_station_id>
		<nas_ip_address>192.168.0.62</nas_ip_address>
		<acct_session_id>00000003</acct_session_id>
		<audit_session_id>0A00640100000011000DE3E7</audit_session_id>
		<server>ISE</server>
		<framed_ip_address>10.0.10.20</framed_ip_address>
		<framed_ipv6_address/>
	</activeSession>
</activeList>"""

#print(ise_xml)
#print("")
#print(asa_json)

def get_isesessions():
    ise_xml_sess = ET.fromstring(ise_xml)
    for session in ise_xml_sess.iter('activeSession'):
        session_ip=session.find('framed_ip_address').text
        session_user=session.find('user_name').text
        session_mac=session.find('calling_station_id').text
        #device_ip = device.find('ip').text
        #device_revs =device.find('latest_revision').text
        print("ID: %s\tName: %s\tMAC: %s" % (session_ip, session_user, session_mac))

def get_isesessions2():
    ise_xml_sess2 = ET.fromstring(isereq.text)
    for session in ise_xml_sess2.iter('activeSession'):
        session_ip=session.find('framed_ip_address').text
        session_user=session.find('user_name').text
        session_mac=session.find('calling_station_id').text
        #device_ip = device.find('ip').text
        #device_revs =device.find('latest_revision').text
        print("ID: %s\tName: %s\tMAC: %s" % (session_ip, session_user, session_mac))
        

def get_asasessions():
    asa_json_sess=json.loads(asa_json)
    for asession in asa_json_sess['items']:
        asession_ip=asession['sourceIp']
        asession_sport=asession['sourcePort']
        #print("Source IP : " + asession["sourceIp"],asession["sourcePort"]["value"])
        #print("Username : " + i["name"],",Privilege Level : ",i["privilegeLevel"])
        print("Source IP : " + asession_ip,",Source Port : ",asession_sport)


def get_asasessions2():
    asa_json_sess=json.loads(asareq.text)
    for asession in asa_json_sess['items']:
        asession_ip=asession['sourceIp']
        asession_sport=asession['sourcePort']
        #print("Source IP : " + asession["sourceIp"],asession["sourcePort"]["value"])
        #print("Username : " + i["name"],",Privilege Level : ",i["privilegeLevel"])
        print("Source IP : " + asession_ip,",Source Port : ",asession_sport)
        
def match_sessions():
    asa_json_sess=json.loads(asa_json)
    ise_xml_sess = ET.fromstring(ise_xml)
    for session in ise_xml_sess.iter('activeSession'):
        session_ip=session.find('nas_ip_address').text
        session_user=session.find('user_name').text
        session_mac=session.find('calling_station_id').text
        for asession in asa_json_sess['items']:
            asession_ip=asession['sourceIp']
            asession_sport=asession['sourcePort']
            if session_ip==asession_ip:
                print(session_user +" has a session on the firewall with the ip: " + asession_ip)

def match_sessions2():
    asa_json_sess=json.loads(asareq.text)
    ise_xml_sess = ET.fromstring(isereq.text)
    for session in ise_xml_sess.iter('activeSession'):
        session_ip=session.find('framed_ip_address').text
        session_user=session.find('user_name').text
        session_mac=session.find('calling_station_id').text
        for asession in asa_json_sess['items']:
            asession_ip=asession['sourceIp']
            asession_sport=asession['sourcePort']
            if session_ip==asession_ip:
                print(session_user +" has a session on the firewall with the ip: " + asession_ip)

def finduser_sessions():
    asa_json_sess=json.loads(asareq.text)
    ise_xml_sess = ET.fromstring(isereq.text)
    for session in ise_xml_sess.iter('activeSession'):
        session_ip=session.find('framed_ip_address').text
        session_user=session.find('user_name').text
        session_mac=session.find('calling_station_id').text
        for asession in asa_json_sess['items']:
            asession_ip=asession['sourceIp']
            asession_sport=asession['sourcePort']
            if session_ip==asession_ip:
                print(session_user +" has a session on the firewall with the ip: " + asession_ip)                

if __name__ == "__main__":
    print("Getting ISE Sessions")
    print("====================")
    print("")
    get_isesessions()
    print("Getting ASA Sessions")
    print("====================")
    print("")
    get_asasessions()
    print("Matching Sessions")
    print("====================")
    print("")
    match_sessions()
    print("Get ISE Data for Real")
    print("====================")
    print("")
    get_isesessions2()
    print("Get ASA Data for Real")
    print("====================")
    print("")
    get_asasessions2()
    print("Matching Sessions for Real")
    print("====================")
    print("")
    match_sessions2()
    finduser=input("Which user are you looking for?")
    print(finduser)
    finduser_sessions()
    pprint(asareq.text)
