import timeit
import winreg
import socket
from scapy.all import*
from types import *
import datetime
import re
#from sets import Set

def listRegKeys(hive, path, computer):
	"""List subkeys for a registry location given the hive (HKLM, HKU, etc.), path (Software\\Microsoft), and target computer
	
	Keyword Arguments:
	
	hive -- the registry hive to target (HKCU, HKLM, etc...)
	
	path --  the path to the registry key to query (Software\\Microsoft)
	
	computer -- the name of the computer to query.  To query local system, pass '.'
	
	Return Value:
	
	List of registry keys
	"""
	result = []
	
	if (hive.lower() == "hklm") or (hive.lower() == "hku") or (hive.lower() == "hkcr"):		
		if (hive.lower() == "hklm"):
			regHandler = winreg.ConnectRegistry(computer,winreg.HKEY_LOCAL_MACHINE)
		elif (hive.lower() == "hku"):
			regHandler = winreg.ConnectRegistry(computer,winreg.HKEY_USERS)
		elif (hive.lower() == "hku"):
			regHandler = winreg.ConnectRegistry(computer,winreg.HKEY_CLASSES_ROOT)
			
		keyHandler = winreg.OpenKey(regHandler,path)		
		index = 0
		while True:
			try:
				result.append(winreg.EnumKey(keyHandler,index))
				index += 1
				
			except EnvironmentError:
				return result			
	else:
		return "invalid hive specified"

def listRegValues(hive, path, computer):
	"""List values for a registry location given the hive (HKLM, HKU, etc.), path (Software\\Microsoft\\CCM), and target computer
	
	Keyword Arguments:
	
	hive -- the registry hive to target (HKCU, HKLM, etc...)
	
	path --  the path to the registry key to query (Software\\Microsoft\\CCM)
	
	computer -- the name of the computer to query.  To query local system, pass '.'
	
	Return Value:
	
	List of tuples (Name, Data, Type)
	"""
	result = []
	
	if (hive.lower() == "hklm") or (hive.lower() == "hku") or (hive.lower() == "hkcr"):		
		if (hive.lower() == "hklm"):
			regHandler = winreg.ConnectRegistry(computer,winreg.HKEY_LOCAL_MACHINE)
		elif (hive.lower() == "hku"):
			regHandler = winreg.ConnectRegistry(computer,winreg.HKEY_USERS)
		elif (hive.lower() == "hku"):
			regHandler = winreg.ConnectRegistry(computer,winreg.HKEY_CLASSES_ROOT)
			
		keyHandler = winreg.OpenKey(regHandler,path)		
		index = 0
		while True:
			try:
				regValue = winreg.EnumValue(keyHandler,index)
				
				if regValue[2] == winreg.REG_DWORD:					
					result.append((regValue[0],regValue[1],"REG_DWORD"))
				elif regValue[2] == winreg.REG_BINARY:					
					result.append((regValue[0],regValue[1],"REG_BINARY"))
				elif regValue[2] == winreg.REG_DWORD_LITTLE_ENDIAN:					
					result.append((regValue[0],regValue[1],"REG_DWORD_LITTLE_ENDIAN"))
				elif regValue[2] == winreg.REG_DWORD_BIG_ENDIAN:					
					result.append((regValue[0],regValue[1],"REG_DWORD_BIG_ENDIAN"))
				elif regValue[2] == winreg.REG_EXPAND_SZ:					
					result.append((regValue[0],regValue[1],"REG_EXPAND_SZ"))
				elif regValue[2] == winreg.REG_LINK:					
					result.append((regValue[0],regValue[1],"REG_LINK"))
				elif regValue[2] == winreg.REG_MULTI_SZ:					
					result.append((regValue[0],regValue[1],"REG_MULTI_SZ"))
				elif regValue[2] == winreg.REG_NONE:					
					result.append((regValue[0],regValue[1],"REG_NONE"))
				elif regValue[2] == winreg.REG_RESOURCE_LIST:					
					result.append((regValue[0],regValue[1],"REG_RESOURCE_LIST"))
				elif regValue[2] == winreg.REG_FULL_RESOURCE_DESCRIPTOR:					
					result.append((regValue[0],regValue[1],"REG_FULL_RESOURCE_DESCRIPTOR"))
				elif regValue[2] == winreg.REG_RESOURCE_REQUIREMENTS_LIST:					
					result.append((regValue[0],regValue[1],"REG_RESOURCE_REQUIREMENTS_LIST"))
				elif regValue[2] == winreg.REG_SZ:					
					result.append((regValue[0],regValue[1],"REG_SZ"))
				else:
					result.append((regValue[0],regValue[1],regValue[2]))				
				index += 1
				
			except EnvironmentError:				
				return result			
	else:
		return "invalid hive specified"		

def passiveOSFingerpring(ip,port):
	"""Attempt to identify the OS of a specified IP given the window size of a TCP packet
	
	Keyword Arguments:
	
	ip -- ip address of target system (string)
	
	port --  port to connect to on target system (int), also takes a list [.,.,.]
	
	Return value:
	
	tuple (ip address, operating system/noReply)
	
	"""
	windowSize = {
		"8192" : "Windows 7, Windows Vista, Windows Server 2008/2012/2016",
		"65392" : "Windows 10",
		"5840" : "Linux (kernel 2.4/2.6)",
		"5720" : "Google Linux",
		"65535" : "Windows XP, FreeBSD",
		"4128" : "Cisco Router (IOS 12.4)"		
	}	
	p = sr1(IP(dst=ip)/TCP(dport=port, flags="S"),timeout=1)	

	if "NoneType" in str(type(p)):	
		return (ip,"noReply")
	else:
		try:
			print("Window Size:\t" + str(p.window))
			os = windowSize[str(p.window)]
		except:
			os = "unknown"
		return (ip,os)

def sophosRebootCheckX64(ip):
	"""Check the remote registry of a specified system to see if a sophos reboot is required.  
	Specifically written for x64 versions of Windows.
	
	Keyword Arguments:
	
	ip -- ip address of target system (string)
	
	Return value:
	
	True -- Reboot Required
	
	False -- Reboot Not Required
	
	Error Message -- Error reading key
	
	"""
	x64reg = "SOFTWARE\\Wow6432Node\\Sophos\\AutoUpdate\\UpdateStatus"	
	try:
		regValues = listRegValues("HKLM",x64reg,ip)
	except IOError as e:
		return e
	for r in regValues:
		if ("result" in r) | ("Result" in r):
			if (r[1] == 0):
				return False
			else:
				return True
	
def sophosServicesCheckX64(ip):
	"""Check the remote registry of a specified system to see if a sophos services are up and running.  
	Specifically written for x64 versions of Windows.
	
	Keyword Arguments:
	
	ip -- ip address of target system (string)
	
	Return value:
	
	Number of degraded services detected (int) or error if can't connect to registry 	
	
	"""
	x64reg = "SOFTWARE\\Wow6432Node\\Sophos\\Health\\Status"	
	degServiceCount = 0
	try:
		regValues = listRegValues("HKLM",x64reg,ip)
	except IOError as e:
		return e
	for r in regValues:
		if ("REG_SZ" == r[2]):
			#degServiceCount = int(r[1]) + degServiceCount
			degServiceCount = 1 + degServiceCount
	return degServiceCount

def sophosDetailedServicesCheckX64(ip):	
	"""Check the remote registry of a specified system to see if a sophos services are up and running.  
	Specifically written for x64 versions of Windows.
	
	Keyword Arguments:
	
	ip -- ip address of target system (string)
	
	Return value:
	
	A tuple containing the number of degraded services detected (int) or error if can't connect to registry and
	a list of degraded service names
	
	"""
	degServiceList = []
	x64reg = "SOFTWARE\\Wow6432Node\\Sophos\\Health\\Status"	
	degServiceCount = 0
	try:
		regValues = listRegValues("HKLM",x64reg,ip)
	except IOError as e:
		return (e,[])
	for r in regValues:
		if ("REG_SZ" == r[2]):
			if (int(r[1]) > 0):			
				degServiceCount = 1 + degServiceCount
				degServiceList.append(r[0].replace("service.",""))							
	#print(degServiceList)
	return (degServiceCount,degServiceList)
	
	
def sophosCommStats(ip):
	"""Check the remote registry of a specified system and report date stamps regarding update statistics
	Specifically written for x64 versions of Windows.
	
	Keyword Arguments:
	
	ip -- ip address of target system (string)
	
	Return value:
	
	Tuple containing multiple timestamps (LastInstallStartTime, LastUpdateTime, LastPowerOneTime, FirstFailedUpdateTime)
	
	"""
	x64reg = "SOFTWARE\\Wow6432Node\\Sophos\\AutoUpdate\\UpdateStatus"
	#Return LastInstallStartTime,LastUpdateTime,LAstPowerOneTime,FirstFailedUpdateTime
	LastInstallStartTime = "NotSet"
	LastUpdateTime = "NotSet"
	LastPowerOneTime = "NotSet"
	FirstFailedUpdateTime = "NotSet"
	
	try:
		regValues = listRegValues("HKLM",x64reg,ip)
	except IOError as e:
		return e
	for r in regValues:
		if "lastinstallstarttime" == str(r[0]).lower():
			#print(r[0] + " --> " + datetime.datetime.utcfromtimestamp(int(r[1])).strftime('%Y-%m-%d %H:%M:%S'))
			LastInstallStartTime = datetime.datetime.utcfromtimestamp(int(r[1])).strftime('%Y-%m-%d %H:%M:%S')
		elif "lastupdatetime" == str(r[0]).lower():
			#print(r[0] + " --> " + datetime.datetime.utcfromtimestamp(int(r[1])).strftime('%Y-%m-%d %H:%M:%S'))
			LastUpdateTime = datetime.datetime.utcfromtimestamp(int(r[1])).strftime('%Y-%m-%d %H:%M:%S')
		elif "lastpowerontime" == str(r[0]).lower():
			#print(r[0] + " --> " + datetime.datetime.utcfromtimestamp(int(r[1])).strftime('%Y-%m-%d %H:%M:%S'))
			LastPowerOneTime = datetime.datetime.utcfromtimestamp(int(r[1])).strftime('%Y-%m-%d %H:%M:%S')
		elif "firstfailedupdatetime" == str(r[0]).lower():
			#print(r[0] + " --> " + datetime.datetime.utcfromtimestamp(int(r[1])).strftime('%Y-%m-%d %H:%M:%S'))
			FirstFailedUpdateTime = datetime.datetime.utcfromtimestamp(int(r[1])).strftime('%Y-%m-%d %H:%M:%S')
	return (LastInstallStartTime,LastUpdateTime,LastPowerOneTime,FirstFailedUpdateTime)
	
def getOSFromReg(ip):
	regKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
	osVer = {
		"5.0" : "Windows 2000",
		"5.1" : "Windows XP",
		"5.2" : "Windows XP 64bit",
		"5.2" : "Windows Server 2003 / R2",
		"6.0" : "Windows Vista / Windows Server 2008",
		"6.1" : "Windows 7 / Windows Server 2008 R2",
		"6.2" : "Windows 8 / Windows Server 2012",
		"6.3" : "Windows 8.1 / Windows Server 2012 R2",
		"10.0" : "Windows 10"
	}
	try:
		regValues = listRegValues("HKLM",regKey,ip)
	except IOError as e:
		return e
	for r in regValues:
		if str(r[0]).lower() == "currentversion":
			value = str(r[1])
	try:
		return osVer[value]
	except:
		return value


def sophosTamperEnabled(ip):
		#reg key to target
		regKey = "SOFTWARE\Sophos\Sophos UI\Policy\DesktopMessaging"
		try:
			#open handle to remote HKLM
			remoteHKLMHandler = winreg.ConnectRegistry(ip,winreg.HKEY_LOCAL_MACHINE)
			#open handle to sophos reg key
			SophosKeyHandler = winreg.OpenKey(remoteHKLMHandler,regKey,0,winreg.KEY_WRITE)
		except:
			return("test failed")
		try:
			#test writing to reg
			winreg.SetValueEx(SophosKeyHandler,"TEST",0,winreg.REG_SZ,"test")
			#if no error was encountered, it was successsful and variable is set
			tamperWorking = "False"
			#delete the created reg value
			winreg.DeleteValue(SophosKeyHandler,"TEST")					
			return(tamperWorking)
		except WindowsError as e:
			#could not write to reg and tamper is working		
			tamperWorking = "True"
			return(tamperWorking)			
		
def main():		
	#print(passiveOSFingerpring("10.140.54.103", 135))
	#print(getOSFromReg("10.8.2.250"))
	#print(gpresultCompare("C:\\Userdata\\MyGPReport.xml","C:\\Userdata\\MyGPReport.xml"))
	print("Main")
	


if __name__ == "__main__":
	main()
	
	
	