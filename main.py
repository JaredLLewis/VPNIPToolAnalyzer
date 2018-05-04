#author: lewis504 
'''
This python program supports several functions to generate report information based on a user inputted txt file.
Description and limitations of reader:
The reader parses specific data laid out by the input file. In this case, the format is very strict. Information that is parsed includes, callingStations, UserNames, Times of login, MacAddresses, and
authentication types. The program can only read txt files for parsing input. The following is the code for the parser:
-----------------------------------------------------------------
    #find ips
    callingStation = "Calling-Station-ID"
    parseGeneralData(element, callingStation, ips)

    #end
    
    #find usernames
    userName = "User-Name"
    parseGeneralData(element, userName, usernames)
    #end
    
    #find Times
    timeSlot = "ise-2017-08-01.gz:"
    parseTimes(element, timeSlot, times)
    
    # mac addresses
    mac = "cisco-av-pair=mdm-tlv=device-mac"
    parseMacData(element, mac, macaddresses)
    
    #device types
    typ = "cisco-av-pair=mdm-tlv=device-type"
    parseGeneralData(element, typ, deviceTypes)    
    #parse citylocations

    #find authetnication types
    auth= "NOTICE"
    parseAuth(element, auth, authenticationTypes)    
-----------------------------------------------------------------


Function 1 - Report all country changes
Description: This function attempts to report all country changes of all users in the input file. This can be very in-efficient for larger txt files.
Uses functions: testUnique(n^2) and alertDifferentCountries(n)

Function 2 - Report all city changes
Description: Very similar to function 1, except returns all city changes.  Can be very in-efficient for larger txt files.
Uses functions: testUnique(n^2) and alertDifferentCities(n)

Function 3 - Report Information about certain user
Description: Allows user to type in a specific user and reports their log, auth attempts, city and country changes and the user's devices, fairly efficient function on larger text files
Uses functions: userInformation, alertDifferentCountries, alertDifferentCities,deviceTypeOfUser,authTypesOfUser  

Function 4 -Report Information about certain ip address
Description: allows a user to report information about a specific ip address. Reports its log, auth attempts city and country changes
Uses functions: ipInformation, alertDifferentCities, alertDifferentCountries, authTypesOfIp

Function 5 - Find repeating information based on threshold
Description: Reports information with thresholding for all parsed data sets. When ips is selected, it also reports the number of different usernames signed in from that ip. Note, this does not
consider whether authentication was failed, session, or success.

Function 6 - Combine file data 
Description: Combines two input files, may be helpful for reading two files. 
Uses: combineFiles

Function 7 - Compare with blacklisted IP File
Description: Compares the ips array with a CSV blacklist file. The ips are parsed from the blacklist file by searching for a specific column that has a list of ips. This is in accordance with the
format of the blacklists given during the project.
Uses: blackList

Function 8 - Quickscan
Description: Performs an overall scan based on several different factors, not a very efficient or helpful function as the cases are limited. Purely for inspectional use
Uses: repeatingIps2, authTypesOfUser

Function 9 - Summary of Usage
Description: Reports a file that contains all failed, succeeded and total auth attempts for each user or ip, depending on user's input. Fairly efficient function.
Uses: sumofusage(for users), sumfofusage2(for ips)

Function 10 - Save Report Information
Description: Saves serialized files to ~/working/savedata of all working arrays. Can occur problems if user accidentally saves over previous information, because of this, this function
should be used carefully. 
Uses: saveInformation

Function 11 - Load Report Information
Description: Loads the serialized files to the working arrays. All loaded data is temporary to the life of the program run. If the program is ended, you will need to re-load the data.
Uses: loadInformation

Function 12 - Top X
Description: Reports top x(specified by user) of the top failed user logins, top failed ip logins, or top failed ip logins excluding US. Only supports export to CSV
Uses: topXipFailed, topXipFailedNoUs, topXuserFailed

Function 13- Exit/Quit
Description: Ends the program via system exit code 0
Uses: nothing

'''



#imports
import re
import mmap
from geolite2 import geolite2 #this import relies on a free geolite database 
import collections
import csv
import os
import pickle
from operator import itemgetter
from distutils.core import setup
import time
#EXE CONFIG

    



#lists
ips = []
usernames = []
lines = []  
cities = []
countries = []
times = []
checked = []
citiesToBeChecked = []
ipInfo = []
macaddresses = []
deviceTypes = []
riskusers = []
riskips = []
authenticationTypes = []

#global var for checking if saved on run
savetest = False

#TODO optimization 

#functions

#blackList -- compares with a CSV file 
def blackList():
    print("This function detects IP octets based on CSV row")
    ans=input("Please enter name of CSV file to input: ")
    check = FileCheck("inputfiles/" + ans + ".csv")
    ans3=input("Enter name of file to output to: ")
    if ans3 == "":
        print("invalid input")
        exit()
    print ("""
    1.CSV
    2.TXT
    """)
    fileType = input("CSV OR TXT?")
    if fileType == "1" or fileType == "2":
        print("")
    else:
        print("invalid input...exiting")
        time.sleep(2)
        exit()
    ipscompare = []
    ipsinformation = []
    ipstype = []
    ipsfinal = []
    if check == 0:
        print("Unable to locate file")
        time.sleep(2)
        exit()
    with open("inputfiles/" + ans + ".csv") as csvfile:
        J = -1
        readCSV = csv.reader(csvfile, delimiter=',')
        reader = csv.reader(csvfile)
        row1 = next(reader)
        row2 = next(reader)
        #extract where to read ip info 
        for i in row2:
            if i.count('.') > 2:
                J = row2.index(i)
        

        csvfile.seek(0) #return to top
        if J == -1:
            print("Error with reading input, unable to find a valid IP")
            time.sleep(2)
            exit()
        for row in readCSV:
            ipscompare.append(row[J])
            try:
                ipsinformation.append(row[J+1])
            except:
                pass
            try:
                ipstype.append(row[J+2])
            except:
                pass
    
    for i in range(len(ips)):
        if ips[i] in ipscompare:
            print("Malicious IP FOUND:" + ips[i])
            index = ipscompare.index(ips[i])
            
            print("Information:" + ipsinformation[index])
            print("Type:" + ipstype[index])
            if fileType == "2":
                try:
                    ipsfinal.append("MATCHED IP:" + ips[i] + ". Country:" + countries[i] + ". City" + cities[i] + ". Information:" + ipsinformation[index] + ". Type:" + ipstype[index])
                except:
                    ipsfinal.append("MATCHED IP: " + ips[i] + "Country:" + countries[i] + "City" + cities[i])
            if fileType == "1":
                try:
                    ipsfinal.append(ips[i] + "," + countries[i] + "," + cities[i] + "," + ipsinformation[index] + "," + ipstype[index])
                except:
                    ipsfinal.append(ips[i] + "," + countries[i] + "," + cities[i])                
                
    
    
    if fileType == "2":
        txtFile = ans3 + ".txt"
            
        try:
            f = open("reports/"+txtFile, "w+")
        except Exception:
            pass
        if len(ipsfinal) == 0:
            f.write("No matches")
        for i in range(len(ipsfinal)):
            f.write(ipsfinal[i])
            f.write("\n")
    if fileType == "1":
        csvfile = ans3 +  ".csv" 
        with open("reports/" + csvfile, "w") as output:
            columnTitleRow = "Matched IP,Country,City,Information,Type \n"
                      
            writer = csv.writer(output, lineterminator='\n')
            output.write(columnTitleRow)        
            for row in ipsfinal:
                output.write(row)
                output.write("\n")            
    
        

#find unique values
def testUniqueO(myList): 
    checked.clear()     
    holder = []
    for z in myList:
        indices = [i for i, x in enumerate(myList) if x == z]
        print(indices)
        if len(indices) > 1:
            
            for e in indices:
                
                if e not in checked:
             
                    checked.append(e)
            checked.append(-1)
    print("time")
    print(checked)

def testUnique(myList):  #O(N*M)
    checked.clear()     
    indices = []
    for z in myList:
        for i,x in enumerate(myList):
            if x == z:
                indices.append(i)
            if len(indices) > 1:
                checked.append(indices[0])
                checked.append(i)
                indices.clear()

#find unique values
def find_index(lst, value, n):
    c=[]
    i=0
    for i, element in enumerate(lst):
        if element == value :
            c .append (i)
        i+=1    
    return c[n]


def testUniqueN(myList): 
    checked.clear()     
    holder = []
    res = []
    for i, z in enumerate(myList):
        if z not in holder:
            holder.append(z)
        else:
            checked.append(holder.index(z))
            checked.append(i)
            z = 0
            i = 0
            holder = []

    print(checked)
        


    
                    
def testUnique2(myList, usr):
    returnlist = []
    for idx, z in enumerate(myList):
        
        if z == usr and z != -1:
            
            returnlist.append(idx)
    
    return returnlist





             

#ensure file exists
def FileCheck(fn):
    try:
        open(fn, "r")
        return 1
    except IOError:
        print("Error: File does not appear to exist.")
        exit()
        return 0


#find different countries in data set
def alertDifferentCountries(ans2, ans3, checked):
    alertedCountries = []
    if len(checked) > 1:
        
        i = 0
        j = 0
        for i in range(len(checked)):
            if checked[i] == -1:
                alertedCountries.append("END")
            try:
               
                if countries[checked[i]] != countries[checked[i+1]] and usernames[checked[i]] == usernames[checked[i+1]]:
                    if checked[i+1] != -1:
                   
                
                        if ans2 == "2":
                            alertedCountries.append("USERNAME: " + usernames[checked[i]] + ". COUNTRY FROM: " + countries[checked[i]] +". IP ADDRESS FROM: " + ips[checked[i]] + ". TIME: " + times[checked[i]] + ". DEVICE FROM: " + deviceTypes[checked[i]])
                            alertedCountries.append("USERNAME: " + usernames[checked[i + 1]] + ". COUNTRY TO: " + countries[checked[i + 1]] + ". IP ADDRESS TO: " + ips[checked[i + 1]] + ". TIME: " + times[checked[i + 1]] + ". DEVICE TO: " + deviceTypes[checked[i+1]])
                        if ans2 == "1":
                            alertedCountries.append(usernames[checked[i]] + "," + countries[checked[i]] + "," + countries[checked[i+1]] + "," + ips[checked[i]] + "," + ips[checked[i+1]] + "," + times[checked[i]] + "," + times[checked[i+1]] + "," +deviceTypes[checked[i]] + "," + deviceTypes[checked[i+1]])
            except IndexError:
           
                break;        
      
           
            

        filtered = list(filter(("END").__ne__, alertedCountries))
        filtered = set(filtered)
        filtered = list(filtered)     
        if ans2 == "2":
          
            txtFile = ans3 + ".txt"
            
            try:
                f = open("reports/"+txtFile, "w+")
            except Exception:
                pass
            if len(filtered) == 0:
                f.write("No Country Changes")
            for i in range(len(filtered)):
                f.write(filtered[i])
                f.write("\n")
            
           
        
        if ans2 == "1": 
            
            csvfile = ans3 + ".csv"
        
            
            with open("reports/"+csvfile, "w") as output:
                writer = csv.writer(output, lineterminator='\n')
                if len(filtered) == 0:
                    writer.writerow(["No Country Changes"])    
                output.write("Username,Country From,Country To, IP From, IP To, Time From, Time To, Device From, Device To")
                output.write("\n")
                for val in filtered:
                    output.write(val)
                    output.write("\n")
                    




                    
def quickScan(ans2, ans3, checked):

    alertedCountries = []
    atRiskUsers = []
    holdere = []
            
            
        
    if len(checked) > 1:
        
        i = 0
        j = 0
        for i in range(len(checked)):
            if checked[i] == -1:
                alertedCountries.append("END")
            try:
                
                fre1,fre2 = authTypesOfUser(usernames[checked[i]])
                
                if "Failed-Attempt: Authentication failed" in fre1:
                    index = fre1.index("Failed-Attempt: Authentication failed")
                    value = fre2[index]
                else:
                    value = 0
                if value > 30:
                    if usernames[checked[i]] not in holdere:
                        holdere.append(usernames[checked[i]])
                        atRiskUsers.append("USERNAME: " + usernames[checked[i]] + ". REASON: Failed Login attempts > 30")
                
                
                
                if countries[checked[i]] != countries[checked[i+1]] and usernames[checked[i]] == usernames[checked[i+1]]:
                    if checked[i+1] != -1:
                        if deviceTypes[checked[i+1]] != deviceTypes[checked[i]]:
                            if deviceTypes[checked[i+1]] != "0" and deviceTypes[checked[i]] != "0":
                                atRiskUsers.append("USERNAME: " + usernames[checked[i]] + ". REASON: Country and Device Change" + ". TIME FROM: " + times[checked[i]] + ". TIME TO: " + times[checked[i+1]] + ". DEVICE FROM: " + deviceTypes[checked[i]] + ". DEVICE TO: " + deviceTypes[checked[i+1]])
                        else:
                            atRiskUsers.append("USERNAME: " + usernames[checked[i]] + ". REASON: Country Change" + ". TIME FROM: " + times[checked[i]] + ". TIME TO: " + times[checked[i+1]] + ". DEVICE FROM: " + deviceTypes[checked[i]] + ". DEVICE TO: " + deviceTypes[checked[i+1]])
                            riskusers.append(usernames[checked[i]])
                
                if cities[checked[i]] != cities[checked[i+1]] and usernames[checked[i]] == usernames[checked[i+1]]:
                  
                    if checked[i+1] != -1:
                   
                
                        if deviceTypes[checked[i+1]] != deviceTypes[checked[i]]:
                          
                            if deviceTypes[checked[i+1]] != "0" and deviceTypes[checked[i]] != "0":
                                
                              
                                a,b = deviceTypeOfUser(usernames[checked[i]])

                                for z in range(len(a)):
                                    if a[z] < 2 and a[z] != "0" and b[z] != "0" and cities[checked[i]] != cities[checked[i+1]]:
                                        atRiskUsers.append("USERNAME: " + usernames[checked[i]] + ". REASON: Device and City Change with New Device: " + ". TIME FROM: " + times[checked[i]] + ". TIME TO: " + times[checked[i+1]] + ". DEVICE FROM: " + deviceTypes[checked[i]] + ". DEVICE TO: " + deviceTypes[checked[i+1]])
                                        
                                
                               
            except IndexError:
                break;        
      
           
        
        box1, box2 = repeatingIps2("1","1")
        filtered = atRiskUsers
        
        if ans2 == "2":
          
            txtFile = ans3 + ".txt"
            
            try:
                f = open("reports/"+txtFile, "w+")
                f.write("Quick Scan Results: ")
                f.write("\n")
            except Exception:
                pass
            for i in range(len(filtered)):
                f.write(filtered[i])
                f.write("\n")
            
           
        
        if ans2 == "1": 
            
            csvfile = ans3 + ".csv"
            
            
            with open("reports/"+csvfile, "w") as output:
                output.write("Quick Scan Results: ")
                output.write("\n")
                writer = csv.writer(output, lineterminator='\n')
                for val in filtered:
                    output.write(val)
                    output.write("\n")
                             


def deviceTypeOfUser(usr):
   
    amounts = []
    devicesloc = []
    devicesloc2 = []
    returnlist = []
    returnlist = testUnique2(usernames, usr)
    
    for i in range(len(returnlist)):
        try:
            
            amounts.append(deviceTypes[returnlist[i]])
        except IndexError:
            pass
        
    
    for x in range(len(amounts)):
        if amounts[x] not in devicesloc2:
            devicesloc.append(amounts.count(amounts[x]))
            devicesloc2.append(amounts[x])
    return devicesloc, devicesloc2


def topXuserFailed(filetype, filename, val):
    arrayhold = []
    valholder = []
    arr = []
    newpath2 = "reports/" + "topx"
    if not os.path.exists(newpath2):
        os.makedirs(newpath2)      
    userTemp = usernames 
    index = 0
    index2 = 0
    value = 0
    value2 = 0
    indspace = " "
    space = "                        "
    for x in range(len(userTemp)):
        leng = len(userTemp[x] + countries[x] + cities[x])
        actual = len(space)-leng
        actual2 = indspace*actual        
        if userTemp[x] in arr:
            m = arr.index(userTemp[x])
            if authenticationTypes[x] == "Failed-Attempt: Authentication failed":
                
                z = arr.index(userTemp[x]) + 1
                newout = int(arr[z]) + 1
                arr[z] = str(newout)
                
            if authenticationTypes[x] == "Passed-Authentication: Authentication succeeded":
                z = arr.index(userTemp[x]) + 2
                newout = int(arr[z]) + 1
                arr[z] = str(newout)   
            else:
                pass
        
        if userTemp[x] not in arr:
            arr.append(userTemp[x])
            if authenticationTypes[x] == "Failed-Attempt: Authentication failed":
                arr.append("1")
            else:
                arr.append("0")
            if authenticationTypes[x] == "Passed-Authentication: Authentication succeeded":
                arr.append("1")
            else:
                arr.append("0")
            if authenticationTypes[x] != "Passed-Authentication: Authentication succeeded" or "Failed-Attempt: Authentication failed":
                pass
        

    for x in range(0, len(arr), 3):
        total = int(arr[x+1]) + int(arr[x+2])
        if filetype == "2":
            arrayhold.append(arr[x] + "," + actual2 + "," + arr[x+1] + "\t\t" + arr[x+2] + "\t\t" + str(total))
        if filetype =="1":
            arrayhold.append(arr[x] + "," + arr[x+1] + "," + arr[x+2] + "," + str(total))
    arrayhold = set(arrayhold)
    arrayhold = sorted(arrayhold)
    arrayhold = list(arrayhold)
    for x in arrayhold:
        stringer = ""
        m = x.index(",") + 1
        z = x.find(",", x.find(",")+1)
        while m < z:
            stringer = stringer + x[m]
            m = m + 1
        
        valholder.append(int(stringer))
    
    indices, valholder_sorted = zip(*sorted(enumerate(valholder), key=itemgetter(1), reverse=True))
    arrayhold2 = []
    for z in indices:
        arrayhold2.append(arrayhold[z])
    
    

    
    
    arrayhold = arrayhold2
    arrayhold =  arrayhold[0:val]
        
    
   
        
    
    if filetype == "1": 
        csvfile = filename + "_topxusedfailed.csv"
         
        with open("reports/topx/" + csvfile, "w") as output:
            columnTitleRow = "UserName, Failed, Success, Total \n"
                      
            writer = csv.writer(output, lineterminator='\n')
            output.write(columnTitleRow)
            for row in arrayhold:
                output.write(row)
                output.write("\n")
            
        
def ncharacter(str1, substr, n):
    pos = -1
    for x in range(n):
        pos = str1.find(substr, pos+1)
        if pos == -1:
            return None
    return pos

def topXipFailed(filetype, filename, val):
    arrayhold = []
    valholder = []
    arr = []
    newpath2 = "reports/" + "topx"
    if not os.path.exists(newpath2):
        os.makedirs(newpath2)      
    userTemp = ips
    index = 0
    index2 = 0
    value = 0
    value2 = 0
    indspace = " "
    space = "                        "
    for x in range(len(userTemp)):
        leng = len(userTemp[x] + countries[x] + cities[x])
        actual = len(space)-leng
        actual2 = indspace*actual        
        if userTemp[x] in arr:
            m = arr.index(userTemp[x])
            if authenticationTypes[x] == "Failed-Attempt: Authentication failed":
                
                z = arr.index(userTemp[x]) + 1
                newout = int(arr[z]) + 1
                arr[z] = str(newout)
                
            if authenticationTypes[x] == "Passed-Authentication: Authentication succeeded":
                z = arr.index(userTemp[x]) + 2
                newout = int(arr[z]) + 1
                arr[z] = str(newout)   
            else:
                pass
        
        if userTemp[x] not in arr:
            arr.append(userTemp[x])
            if authenticationTypes[x] == "Failed-Attempt: Authentication failed":
                arr.append("1")
            else:
                arr.append("0")
            if authenticationTypes[x] == "Passed-Authentication: Authentication succeeded":
                arr.append("1")
            else:
                arr.append("0")
            if authenticationTypes[x] != "Passed-Authentication: Authentication succeeded" or "Failed-Attempt: Authentication failed":
                pass

    for x in range(0, len(arr), 3):
        total = int(arr[x+1]) + int(arr[x+2])
        if filetype == "2":
            arrayhold.append(arr[x] + "," + countries[x] + "," + cities[x] + "," + actual2 + "," + arr[x+1] + "\t\t" + arr[x+2] + "\t\t" + str(total))
        if filetype =="1":
            arrayhold.append(arr[x] + "," + countries[x] + "," + cities[x] + "," + arr[x+1] + "," + arr[x+2] + "," + str(total))   
                
    arrayhold = set(arrayhold)
    arrayhold = sorted(arrayhold)
    arrayhold = list(arrayhold)
    if len(arrayhold) < 1:
        print("None Exist, no file made")
        return "None"
    for x in arrayhold:
        stringer = ""
        m = ncharacter(x, ",", 3) + 1
        z = ncharacter(x, ",", 4)
        while m < z:
            stringer = stringer + x[m]
            m = m + 1
        
        valholder.append(int(stringer))
    
    indices, valholder_sorted = zip(*sorted(enumerate(valholder), key=itemgetter(1), reverse=True))
    arrayhold2 = []
    for z in indices:
        arrayhold2.append(arrayhold[z])
    
    
    arrayhold = arrayhold2
    arrayhold =  arrayhold[0:val]
    
    if filetype == "1": 
        csvfile = filename + "_topxipfailed.csv"
          
        with open("reports/topx/" + csvfile, "w") as output:
            columnTitleRow = "CallingStation,City,Country, Failed, Success, Total \n"
                      
            writer = csv.writer(output, lineterminator='\n')
            output.write(columnTitleRow)
            for row in arrayhold:
                output.write(row)
                output.write("\n")


def topXipFailedNoUs(filetype, filename, val):
    arrayhold = []
    valholder = []
    arr = []
    newpath2 = "reports/" + "topx"
    if not os.path.exists(newpath2):
        os.makedirs(newpath2)      
    userTemp = ips
    index = 0
    index2 = 0
    value = 0
    value2 = 0
    indspace = " "
    space = "                        "
    for x in range(len(userTemp)):
        leng = len(userTemp[x] + countries[x] + cities[x])
        actual = len(space)-leng
        actual2 = indspace*actual        
        if userTemp[x] in arr:
            m = arr.index(userTemp[x])
            if authenticationTypes[x] == "Failed-Attempt: Authentication failed":
                
                z = arr.index(userTemp[x]) + 1
                newout = int(arr[z]) + 1
                arr[z] = str(newout)
                
            if authenticationTypes[x] == "Passed-Authentication: Authentication succeeded":
                z = arr.index(userTemp[x]) + 2
                newout = int(arr[z]) + 1
                arr[z] = str(newout)   
            else:
                pass
        
        if userTemp[x] not in arr:
            arr.append(userTemp[x])
            if authenticationTypes[x] == "Failed-Attempt: Authentication failed":
                arr.append("1")
            else:
                arr.append("0")
            if authenticationTypes[x] == "Passed-Authentication: Authentication succeeded":
                arr.append("1")
            else:
                arr.append("0")
            if authenticationTypes[x] != "Passed-Authentication: Authentication succeeded" or "Failed-Attempt: Authentication failed":
                pass

    for x in range(0, len(arr), 3):
        total = int(arr[x+1]) + int(arr[x+2])
        if filetype == "2":
            arrayhold.append(arr[x] + "," + countries[x] + "," + cities[x] + "," + actual2 + "," + arr[x+1] + "\t\t" + arr[x+2] + "\t\t" + str(total))
        if filetype =="1":
            if "'US'" not in countries[x]:
                arrayhold.append(arr[x] + "," + countries[x] + "," + cities[x] + "," + arr[x+1] + "," + arr[x+2] + "," + str(total))    
    
    
    

                
    arrayhold = set(arrayhold)
    arrayhold = sorted(arrayhold)
    arrayhold = list(arrayhold)
    if len(arrayhold) < 1:
        print("None Exist, no file made")
        return "None"
    for x in arrayhold:
        stringer = ""
        m = ncharacter(x, ",", 3) + 1
        z = ncharacter(x, ",", 4)
        while m < z:
            stringer = stringer + x[m]
            m = m + 1
        
        valholder.append(int(stringer))
    
    indices, valholder_sorted = zip(*sorted(enumerate(valholder), key=itemgetter(1), reverse=True))
    arrayhold2 = []
    for z in indices:
        arrayhold2.append(arrayhold[z])
    
    
    arrayhold = arrayhold2
    arrayhold =  arrayhold[0:val]
    
    if filetype == "1": 
        csvfile = filename + "_topxipfailed.csv"
          
        with open("reports/topx/" + csvfile, "w") as output:
            columnTitleRow = "CallingStation,City,Country, Failed, Success, Total \n"
                      
            writer = csv.writer(output, lineterminator='\n')
            output.write(columnTitleRow)
            for row in arrayhold:
                output.write(row)
                output.write("\n")





        
def sumofusage(filetype, filename):
    newpath =  "sum"
    arrayhold = []
    valholder = []
    newpath2 = "reports/" + "sum"
    if not os.path.exists(newpath2):
        os.makedirs(newpath2)      
    userTemp = usernames
    txtFile = newpath + "/" + filename + "_authattempts.txt" 
    index = 0
    index2 = 0
    value = 0
    value2 = 0
    indspace = " "
    space = "                        "
    arr = []
    for x in range(len(userTemp)):
        leng = len(userTemp[x] + countries[x] + cities[x])
        actual = len(space)-leng
        actual2 = indspace*actual
        
        if userTemp[x] in arr:
            m = arr.index(userTemp[x])
            if authenticationTypes[x] == "Failed-Attempt: Authentication failed":
                
                z = arr.index(userTemp[x]) + 1
                newout = int(arr[z]) + 1
                arr[z] = str(newout)
                
            if authenticationTypes[x] == "Passed-Authentication: Authentication succeeded":
                z = arr.index(userTemp[x]) + 2
                newout = int(arr[z]) + 1
                arr[z] = str(newout)   
            else:
                pass
        
        if userTemp[x] not in arr:
            arr.append(userTemp[x])
            if authenticationTypes[x] == "Failed-Attempt: Authentication failed":
                arr.append("1")
            else:
                arr.append("0")
            if authenticationTypes[x] == "Passed-Authentication: Authentication succeeded":
                arr.append("1")
            else:
                arr.append("0")
            if authenticationTypes[x] != "Passed-Authentication: Authentication succeeded" or "Failed-Attempt: Authentication failed":
                pass
        

    for x in range(0, len(arr), 3):
        total = int(arr[x+1]) + int(arr[x+2])
        if filetype == "2":
            leng = len(arr[x])
            actual = len(space)-leng
            actual2 = indspace*actual            
            arrayhold.append(arr[x] + "," + actual2 + arr[x+1] + "\t\t" + arr[x+2] + "\t\t" + str(total))
        if filetype =="1":
            arrayhold.append(arr[x] + "," + arr[x+1] + "," + arr[x+2] + "," + str(total))
   
        
    
      
    arrayhold = set(arrayhold)
    arrayhold = sorted(arrayhold)
    arrayhold = list(arrayhold)
    for x in arrayhold:
        stringer = ""
        m = x.index(",") + 1
        z = x.find(",", x.find(",")+1)
        while m < z:
            stringer = stringer + x[m]
            m = m + 1
        
        valholder.append(stringer)
    
    indices, valholder_sorted = zip(*sorted(enumerate(valholder), key=itemgetter(1)))
    
    
   
        
    if filetype == "2":
        f = open("reports/"+txtFile, "w+")
        f.write("UserName\t\tFailed\t\tSuccess\t\tTotal")
        f.write("\n")
        for i in range(len(arrayhold)):
            f.write(arrayhold[i])
            f.write("\n")
        f.close()
        f = open("reports/"+txtFile, "r")
        s = f.read()    
    
    if filetype == "1": 
        csvfile = filename + "_authattempts.csv"
            #Assuming res is a flat list
        with open("reports/sum/" + csvfile, "w") as output:
            columnTitleRow = "UserName, Failed, Success, Total \n"
                      
            writer = csv.writer(output, lineterminator='\n')
            output.write(columnTitleRow)
            for row in arrayhold:
                output.write(row)
                output.write("\n")
            
            
    
    
def sumofusage2(filetype, filename):
    newpath =  "sum"
    arrayhold = []
    arr = []
    newpath2 = "reports/" + "sum"
    if not os.path.exists(newpath2):
        os.makedirs(newpath2)      
    userTemp = ips
    txtFile = newpath + "/" + filename + "_authattempts.txt" 
    index = 0
    index2 = 0
    value = 0
    value2 = 0
    indspace = " "
    
    space = "                                                            "
    
    
    
    for x in range(len(userTemp)):
         
        if userTemp[x] in arr:
            m = arr.index(userTemp[x])
            if authenticationTypes[x] == "Failed-Attempt: Authentication failed":
                
                z = arr.index(userTemp[x]) + 1
                newout = int(arr[z]) + 1
                arr[z] = str(newout)
                
            if authenticationTypes[x] == "Passed-Authentication: Authentication succeeded":
                z = arr.index(userTemp[x]) + 2
                newout = int(arr[z]) + 1
                arr[z] = str(newout)   
            else:
                pass
        
        if userTemp[x] not in arr:
            arr.append(userTemp[x])
            if authenticationTypes[x] == "Failed-Attempt: Authentication failed":
                arr.append("1")
            else:
                arr.append("0")
            if authenticationTypes[x] == "Passed-Authentication: Authentication succeeded":
                arr.append("1")
            else:
                arr.append("0")
            if authenticationTypes[x] != "Passed-Authentication: Authentication succeeded" or "Failed-Attempt: Authentication failed":
                pass

    for x in range(0, len(arr), 3):
        
        total = int(arr[x+1]) + int(arr[x+2])
        if filetype == "2":
            leng = len(userTemp[x] + countries[x] + cities[x])
            actual = len(space)-leng
            actual2 = indspace*actual              
            arrayhold.append(arr[x] + "," + countries[x] + "," + cities[x] + "," + actual2 + "\t\t" + arr[x+1] + "\t\t" + arr[x+2] + "\t\t" + str(total))
        if filetype =="1":
            arrayhold.append(arr[x] + "," + countries[x] + "," + cities[x] + "," + arr[x+1] + "," + arr[x+2] + "," + str(total))
        
    
    arrayhold = set(arrayhold)    
    arrayhold = sorted(arrayhold)
    arrayhold = list(arrayhold)
    if filetype == "2":
        f = open("reports/"+txtFile, "w+")
        f.write("IP Address Information" + actual2 + "\t\t\t\tFailed\t\tSuccess\t\tTotal")
        f.write("\n")
        for i in range(len(arrayhold)):
            f.write(arrayhold[i])
            f.write("\n")
        f.close()
        f = open("reports/"+txtFile, "r")
        s = f.read()
    if filetype == "1": 
        csvfile = filename +  "_authattempts.csv" 
        with open("reports/sum/" + csvfile, "w") as output:
            columnTitleRow = "IP, Country, City, Failed, Success, Total \n"
                      
            writer = csv.writer(output, lineterminator='\n')
            output.write(columnTitleRow)
            for row in arrayhold:
                output.write(row)
                output.write("\n")
            
        





    
def authTypesOfUser(usr):

    amounts = []
    devicesloc = []
    devicesloc2 = []
    returnlist = []
    returnlist = testUnique2(usernames, usr)
    

    for i in range(len(returnlist)):
        try:

            amounts.append(authenticationTypes[returnlist[i]])
        except IndexError:
            pass


    for x in range(len(amounts)):
        if amounts[x] not in devicesloc2:
            if amounts[x] != "0":
                devicesloc.append(amounts.count(amounts[x]))
                devicesloc2.append(amounts[x])
    mounts = set(amounts)
    types = list(mounts)
    return types, devicesloc   


def authTypesOfIp(ip):

    amounts = []
    devicesloc = []
    devicesloc2 = []
    returnlist = []
    returnlist = testUnique2(ips, ip)


    for i in range(len(returnlist)):
        try:

            amounts.append(authenticationTypes[returnlist[i]])
        except IndexError:
            pass


    for x in range(len(amounts)):
        if amounts[x] not in devicesloc2:
            devicesloc.append(amounts.count(amounts[x]))
            devicesloc2.append(amounts[x])
    
    mounts = set(amounts)
    types = list(mounts)    

    return types, devicesloc  

#find different cities in data set  
def alertDifferentCities(ans2, ans3, checked):
    alertedCountries = []
    if len(checked) > 1:
        
        i = 0
        j = 0
        for i in range(len(checked)):
            if checked[i] == -1:
                alertedCountries.append("END")
            try:              
                if cities[checked[i]] != cities[checked[i+1]] and usernames[checked[i]] == usernames[checked[i+1]]:
                    if checked[i+1] != -1:
                        
                        if ans2 == "2":
                            alertedCountries.append("USERNAME: " + usernames[checked[i]] + ". CITY FROM: " + cities[checked[i]] +". IP ADDRESS FROM: " + ips[checked[i]] + ". TIME: " + times[checked[i]] + ". DEVICE FROM: " + deviceTypes[checked[i]])
                            alertedCountries.append("USERNAME: " + usernames[checked[i + 1]] + ". CITY TO: " + cities[checked[i + 1]] + ". IP ADDRESS TO: " + ips[checked[i + 1]] + ". TIME: " + times[checked[i + 1]] + ". DEVICE TO: " + deviceTypes[checked[i+1]])
                        if ans2 == "1":
                            if ans2 == "1":
                                
                                alertedCountries.append(usernames[checked[i]] + "," + cities[checked[i]] + "," + cities[checked[i+1]] + "," + ips[checked[i]] + "," + ips[checked[i+1]] + "," + times[checked[i]] + "," + times[checked[i+1]] + "," +deviceTypes[checked[i]] + "," + deviceTypes[checked[i+1]])                            
            except IndexError:
                
                break;        
      
           
            
       
            
        filtered = list(filter(("END").__ne__, alertedCountries))
        filtered = list(set(filtered))
        if ans2 == "2":
          
            txtFile = ans3 + ".txt"
            f = open("reports/" + txtFile, "w+")
            if len(filtered) == 0:
                f.write("No City Changes")            
            for i in range(len(filtered)):
                f.write(filtered[i])
                f.write("\n")
            f.close()
            f = open("reports/"+txtFile, "r")
            s = f.read()
         
        
        if ans2 == "1": 
            
            csvfile = ans3 + ".csv"
        
            #Assuming res is a flat list
            with open("reports/" + csvfile, "w") as output:
                writer = csv.writer(output, lineterminator='\n')
                if len(filtered) == 0:
                    writer.writerow(["No City Changes"])   
                output.write("Username, City From, City To, IP From, IP To, Time From, Time To, Device From, Device To")
                output.write("\n")
                for val in filtered:
                    output.write(val)
                    output.write("\n")
                    
      
#filter by user
def userInformation(usr, fileType):
    checked2  = []
    userInfo = []
    fre1 = []
    fre2 = []
    indices =[]
    count = usernames.count(usr)

    
    if count == 0:
        print("No such user found")
    else:
        for i, e in enumerate(usernames):
            if usernames[i] == usr:
                indices.append(i)
        
        
        if fileType == "2":    
            userInfo.append("Total Occurences: " + str(count))
        for i in indices:
            if fileType == "2":
                userInfo.append("USERNAME: " + usernames[i] + ". COUNTRY: " + countries[i] + ". CITY: " + cities[i] +". IP ADDRESS: " + ips[i] + ". TIME: " + times[i] + ". DEVICE: " + deviceTypes[i] + ". Authentication:" + authenticationTypes[i])
            if fileType == "1":
                userInfo.append(usernames[i] + "," + countries[i] + "," + cities[i] + "," + ips[i] + "," + times[i] + "," + deviceTypes[i] + "," + authenticationTypes[i])
  
        
        newpath =  usr
        newpath2 = "reports/" + usr
        if not os.path.exists(newpath2):
            os.makedirs(newpath2)  
        checked2 = indices
        alertDifferentCountries(fileType, newpath + "/" + usr + "_countries", indices)
        alertDifferentCities(fileType, newpath + "/" + usr + "_cities", indices)  
        a,b = deviceTypeOfUser(usr)
        fre1,fre2 = authTypesOfUser(usr)
        
        if fileType == "2":
            txtFile = newpath + "/" + usr + "_log.txt"   
            f = open("reports/"+txtFile, "w+")
            f.write("Device logged in from count")
            f.write("\n")
            for z in range(len(a)):
                f.write(b[z])
                f.write(": ")
                f.write(str(a[z]))
                f.write("\n")
            f.write("\n")
            for i in range(len(userInfo)):
                f.write(userInfo[i])
                f.write("\n")
            f.close()
            
            
            txtFile = newpath + "/" + usr + "_authattempts.txt"   
            f = open("reports/"+txtFile, "w+")
            f.write("Authentication Count")
            f.write("\n")
            total = 0
            for z in range(len(fre2)):
                if "Session" not in str(fre1[z]):
                    total += fre2[z]
                f.write(str(fre1[z]))
                f.write(": ")
                f.write(str(fre2[z]))
                f.write("\n")
            if "Session Login" in fre1:
                fre1.remove("Session Login")
            f.write("Total Failed/Succeeded Authentication: " + str(total))
            f.close()
        if fileType == "1": 
            csv1 = []
            csvfile = newpath + "/" + usr + "_log.csv"
            csv1.append("Device Logged In From Count")
            for z in range(len(a)):
                csv1.append(str(b[z]) + ": " + str(a[z]))
            with open("reports/"+csvfile, "w") as output:
                
                writer = csv.writer(output, lineterminator='\n')
                for m in csv1:
                    writer.writerow([m])
                output.write("Total Occurences: " + str(count))
                output.write("\n")
                output.write("User,Country,City,IP,Time,Device,Authentication")
                output.write("\n")
                for val in userInfo:
                    output.write(val)
                    output.write("\n")
            
            csv2 = []
            csv3 = []
            total = 0
            for z in range(len(fre2)):
             
                csv2.append(usr + "," +  str(fre1[z]) + "," + str(fre2[z]) + ",")
                if "Session" not in str(fre1[z]):
                    total += fre2[z]
            csvfile = newpath + "/" + usr + "_authattempts.csv"
            
                
            with open("reports/"+csvfile, "w") as output:
                output.write("Total Logins," + str(total))
                output.write("\n")
                output.write("User, Login Type, Number")
                output.write("\n")
               
                writer = csv.writer(output, lineterminator='\n')
                for row in csv2:
                    output.write(row)
                    output.write("\n")                

#filter by ip        
def ipInformation(ip, fileType):
    ipInfo = []
    indices = []
    count = ips.count(ip)
    if count == 0:
        print("No such ip found")
    else:
        for i, e in enumerate(ips):
            if ips[i] == ip:
                indices.append(i)    
            
        ipInfo.append("Total Occurences: " + str(count))
        for i in indices:
            if fileType == "2":
                ipInfo.append("USERNAME: " + usernames[i] + ". COUNTRY: " + countries[i] + ". CITY: " + cities[i] + ". IP ADDRESS: " + ips[i] + ". TIME: " + times[i] + ". DEVICE: " + deviceTypes[i] + ". Authentication:" + authenticationTypes[i] )
            if fileType == "1":
                ipInfo.append(usernames[i] + "," + countries[i] + "," + cities[i] + "," + ips[i] + "," + times[i] + "," + deviceTypes[i] + "," + authenticationTypes[i])                
        
        newpath = ip
        newpath2 = "reports/" + ip
        if not os.path.exists(newpath2):
            os.makedirs(newpath2)  
        checked2 = indices     
        alertDifferentCountries(fileType, newpath + "/" + ip + "_countries", checked2)
        alertDifferentCities(fileType, newpath + "/" + ip + "_cities", checked2)  
        fre1,fre2 = authTypesOfIp(ip)
        if fileType == "2":
              
            txtFile = newpath + "/" + ip + "_log.txt"   
            f = open("reports/" + txtFile, "w+")
            for i in range(len(ipInfo)):
                f.write(ipInfo[i])
                f.write("\n")
            f.close()
            
            txtFile = newpath + "/" + ip + "_authattempts.txt"   
            f = open("reports/"+txtFile, "w+")
            f.write("Authentication Count")
            f.write("\n")
            total = 0
            for z in range(len(fre2)):
                f.write(str(fre1[z]))
                f.write(": ")
                f.write(str(fre2[z]))
                f.write("\n")
                if "Session" not in str(fre1[z]):
                    total += fre2[z]
            
            f.write("Total Failed/Succeeded Authentication: " + str(total))
            f.close()            
            
        if fileType == "1": 
                
            csvfile = newpath + "/" + ip + "_log.csv"
            
                
            with open("reports/" + csvfile, "w") as output:
                writer = csv.writer(output, lineterminator='\n')
                output.write("Username, Country, Cities, IP, Time, DeviceType, Authentication")
                output.write("\n")
                for val in ipInfo:
                    output.write(val)
                    output.write("\n")
            csv2 = []
            csv3 = []
            total = 0
            for z in range(len(fre2)):
        
                csv2.append(ip + "," +  str(fre1[z]) + "," + str(fre2[z]) + ",")
                if "Session" not in str(fre1[z]):
                    total += fre2[z]
            csvfile = newpath + "/" + ip + "_authattempts.csv"
        
        
            with open("reports/"+csvfile, "w") as output:
                output.write("Total Logins," + str(total))
                output.write("\n")
                output.write("CallingStation, Login Type, Number")
                output.write("\n")
                writer = csv.writer(output, lineterminator='\n')
                for row in csv2:
                    output.write(row)
                    output.write("\n")    
         
            
#combining files
def combineFiles(file1, file2, output):
    file1 += ".txt"
    file2 += ".txt"
    output += ".txt"
    filenames = [file1, file2]
    with open("combinedfiles/" + output, 'w') as outfile:
        for fname in filenames:
            try:
                with open("combinedfiles/" + fname) as infile:
                    for line in infile:
                        outfile.write(line) 
            except:
                print("File does not exist.")



def saveInformation(): #uses pickle to deserialize for very quick save/load

    
  
    
    
    with open('savedata/userdata', 'ab') as fp:
        pickle.dump(usernames, fp)  
    with open('savedata/ipsdata', 'ab') as fp:
        pickle.dump(ips, fp)
    with open('savedata/countriesdata', 'ab') as fp:
        pickle.dump(countries, fp)
    with open('savedata/citiesdata', 'ab') as fp:
        pickle.dump(cities, fp)
    with open('savedata/timesdata', 'ab') as fp:
        pickle.dump(times, fp)
    with open('savedata/macaddressesdata', 'ab') as fp:
        pickle.dump(macaddresses, fp)     
    with open('savedata/authdata', 'ab') as fp:
        pickle.dump(authenticationTypes, fp)   
    with open('savedata/devicetypedata', 'ab') as fp:
        pickle.dump(deviceTypes, fp)       
    
    

def loadInformation():
    

    
    with open ('savedata/userdata', 'rb') as fp:
        userlist = pickle.load(fp)
        usernames.extend(userlist)
    with open ('savedata/ipsdata', 'rb') as fp:
        ipslist = pickle.load(fp)
        ips.extend(ipslist)
    with open ('savedata/countriesdata', 'rb') as fp:
        countrieslist = pickle.load(fp)
        countries.extend(countrieslist)
    with open ('savedata/citiesdata', 'rb') as fp:
        citieslist = pickle.load(fp)
        cities.extend(citieslist)
    with open ('savedata/timesdata', 'rb') as fp:
        timeslist = pickle.load(fp)
        times.extend(timeslist)
    with open ('savedata/macaddressesdata', 'rb') as fp:
        maclist = pickle.load(fp)
        macaddresses.extend(maclist)
    with open ('savedata/authdata', 'rb') as fp:
        authlist = pickle.load(fp)
        authenticationTypes.extend(authlist)  
    with open ('savedata/devicetypedata', 'rb') as fp:
        devicelist = pickle.load(fp)
        deviceTypes.extend(devicelist)          
    
    
    
    
#repeating information  
def repeatingIps(threshold, arrChoice, fileType, fileName):
    arrPick = [];
    opt2 = [];
    opt = [];
    opt3 = []
    userPick = [];
    allMarked = [];
    
    
    if arrChoice == "1":
        arrPick = ips
        userPick = usernames
        
    elif arrChoice == "2":
        arrPick = usernames
        userPick = ips
    elif arrChoice == "3":
        arrPick = cities
        userPick = cities
    elif arrChoice == "4":
        arrPick = countries
        userPick = countries
    elif arrChoice == "5":
        arrPick = times
        userPick = times
    elif arrChoice == "6":
        arrPick = deviceTypes
        userPick = deviceTypes
    elif arrChoice == "7":
        arrPick = macaddresses    
        userPick = macaddresses
        
        print ("""
        1.ips
        2.usernames
        3.cities
        4.countries
        5.times
        """)
        
    iphold = []
    userhold = []
    temp = []
    for item, item2 in zip(arrPick, userPick):
        m = 0
        
        if arrPick.count(item) > int(threshold):
                  
            opt.append(item)
            
        if arrChoice == "1" and arrPick.count(item) > int(threshold): #marked IPS only for IPs
            for i, j in enumerate(ips):
                if j == item and usernames[i] != item2:
                    userhold.append(usernames[i])
                    
                    
            if item not in temp:
                temp.append(item)
                
                marked = (set(userhold))
                allMarked.append(len(marked))
                userhold = []
                m = m +1
            else:
                userhold = []

    temp = []
    userhold = []
    myset = set(opt)
    opt = list(myset)
        
    for i in range(len(opt)):
        opt2.append(arrPick.count(opt[i]))

    if fileType == "2":
        
      
        txtFile = fileName + ".txt"   
        f = open("reports/"+txtFile, "w+")
        for i in range(len(opt)):
            f.write(opt[i])
            f.write("---Occurences: ")
            f.write(str(arrPick.count(opt[i])))
            
            if arrChoice == "1":
                f.write("---Different Login Count: ")
                f.write(str(allMarked[i]))   
                f.write("\n")
            if arrChoice == "2":
                f.write("---Different IP Count: ")
                f.write(str(allMarked[i]))                  
                f.write("\n")
            else:
                f.write("\n")
        f.close()
        f = open("reports/"+txtFile, "r")
        s = f.read()
      
    
    if fileType == "1": 
        
        csvfile = fileName + ".csv"
    
        with open("reports/"+csvfile, "w") as output:
            output.write("Item, Occurences, Different Login/IP Count(if applicable)")
            output.write("\n")
            writer = csv.writer(output, lineterminator='\n')
            if arrChoice == "1":
                for val, x, z  in zip(opt, opt2, allMarked):
                    writer.writerow([val] + [x] + [z])
            else:
                for val, x  in zip(opt, opt2):
                    writer.writerow([val] + [x])                
                
                
                
    
    
def repeatingIps2(threshold, arrChoice):
    
    
    arrPick = [];
    final = [];
    final2 = [];
    opt2 = [];
    opt = [];
    opt3 = []
    userPick = [];
    allMarked = [];
    
    
    if arrChoice == "1":
        arrPick = ips
        userPick = usernames
        
    
    for item, item2 in zip(arrPick, userPick): 
        opt.append(item)
            
        if arrChoice == "1": #marked IPS only for IPs
            
            
            for index, value in enumerate(arrPick):
                if value == item:
                    opt3.append(usernames[index])
      
            marked = len(set(opt3))
           
            allMarked.append(marked)
            opt3 = [];
          
    
    for i in range(len(opt)):
        opt2.append(arrPick.count(opt[i]))
    for i in range(len(opt)):
        if (allMarked[i] > 2):
            
            final.append(opt[i])
            final2.append(allMarked[i])
        
 
    return final, final2 
    




#used to parse most data
def parseGeneralData(string, substring, listAdd):
    idx = string.find(substring)
    subs = element[:idx+len(substring) + 1]
    m = element.replace(subs, '')
    invip = m[:m.index(",")]
    if len(invip) < 40:
        listAdd.append(invip)
    else:
        listAdd.append("0") #unfound data

def parseAuth(string, substring, listAdd):
    idx = string.find(substring)
    subs = element[:idx+len(substring) + 1]
    m = element.replace(subs, '')
    invip = m[:m.index(",")]
    if invip == 'Passed-Authentication: Authentication succeeded' or invip == 'Failed-Attempt: Authentication failed': #These are two cases, authentication failed or succeeded,
        
        listAdd.append(invip)
    else: #this means the NOTICE data is session data, therefore ignoring at this time as not tracking such info.
        listAdd.append("Session Login")
        


 
#specific for mac data 
def parseMacData(string, substring, listAdd):
    idx = string.find(substring)
    subs = element[:idx+len(substring) + 1]
    m = element.replace(subs, '')
    invip = m[:m.index(",")]
    if len(invip) < 30: #ensure mac address, if not, then must be phone address
        listAdd.append(invip)
    else:
        idx = string.find("cisco-av-pair=mdm-tlv=device-phone-id")
        
        subs = element[:idx+len(substring) + 1]
        m = element.replace(subs, '')
      
        invip = m[:m.index(",")]

        if len(invip) < 30:
            listAdd.append(invip)
        else:
            listAdd.append("0") #no mac address available for data
        
   
   


#specific for time data
def parseTimes(string, substring, listAdd): #slightly different format, hence new method
    idx = string.find(substring)
    subs = element[:idx+len(substring)]
    m = element.replace(subs, '')
    invip = m[:m.index("muise")]
    count = 0
    timeString = ""
    for c in invip:
        count = count + 1
        if count > 6:
            timeString += c
    
        
    
    
    listAdd.append(invip)
    
    



def parseLocations(match, ip):
    #city
    if match == "0":
        cities.append("0")
        countries.append("0")
    else:
        stringMatch = str(match)
        idx = stringMatch.find("names")
        subs2 = stringMatch[:idx+len("names") + 1]
        d = stringMatch.replace(subs2, '')
        invip2 = d[:d.index(",")]
        a = invip2.replace("{",""); #remove left bracket
        cities.append(a)
        #end city
    
        #country
        idx = stringMatch.find("iso_code")
        subs2 = stringMatch[:idx+len("iso_code") + 1]
        d = stringMatch.replace(subs2, '')
        invip2 = d[:d.index(",")]
        a = invip2.replace(":",""); #remove semicolon 
        countries.append(a)
    
#END OF METHODS





#MAIN
print("Please enter name of file to input without the extension.")
ans=input("Please make sure this file is in the inputfiles directory: ")
ans += ".txt"
check = FileCheck("inputfiles/" + ans)
if check == 0:
    time.sleep(2)
    exit()
in_file = open("inputfiles/" + ans)
for line in in_file:  
    lines.append(line.rstrip('\n'))   
for element in lines:            
    
    
    #find ips
    callingStation = "Calling-Station-ID"
    parseGeneralData(element, callingStation, ips)

    #end
    
    #find usernames
    userName = "User-Name"
    parseGeneralData(element, userName, usernames)
    #end
    
    #find Times
    timeSlot = "ise-2017-08-01.gz:"
    parseTimes(element, timeSlot, times)
    
    # mac addresses
    mac = "cisco-av-pair=mdm-tlv=device-mac"
    parseMacData(element, mac, macaddresses)
    
    #device types
    typ = "cisco-av-pair=mdm-tlv=device-type"
    parseGeneralData(element, typ, deviceTypes)    
    #parse citylocations

    #find authetnication types
    auth= "NOTICE"
    parseAuth(element, auth, authenticationTypes)    



for item in ips:
    reader = geolite2.reader()
    try:
        match = reader.get(item)
    except:
        match = "0" #invalid ip
    parseLocations(match, item) 
 
in_file.close 
if not os.path.exists("reports"):
    os.makedirs("reports")  
if not os.path.exists("combinedfiles"):
    os.makedirs("combinedfiles") 
if not os.path.exists("inputfiles"):
    os.makedirs("inputfiles") 

print("File Successfully Read")

ans=True
while ans:
      
    print ("""
    1.Report all country changes
    2.Report all city changes
    3.Report information about certain user
    4.Report information about certain IP Address 
    5.Find repeating information based on threshold
    6.Combine file data
    7.Compare with blacklisted IP file
    8.QuickScan
    9.Summary of Usage
    10.Save Report Information
    11.Load Report Information
    12.Top X
    13.Exit/Quit
    """)

    ans=input("What would you like to do? ") 
    
    if ans=="1": 
        print ("""
    1.CSV
    2.TXT
    """)
        
        ans2 = input("CSV OR TXT?")

        if ans2 == "1" or ans2 == "2":
            ans3 = input("Please Enter Name of File: ")
            if ans3 != "":
                testUnique(usernames)
                alertDifferentCountries(ans2, ans3, checked)
        elif ans2 !="":
            print("\n Not Valid Choice Try again")
            
        
    elif ans=="2":
            print ("""
    1.CSV
    2.TXT
    """)
            ans2 = input("CSV OR TXT?")
            if ans2 == "1" or ans2 == "2":
                ans3 = input("Please Enter Name of File: ")
                if ans3 != "":
                    testUnique(usernames)
                    alertDifferentCities(ans2, ans3, checked)
                elif ans !="":
                    print("\n Not Valid Choice Try again")
    elif ans=="3":
        usr = input("Enter User Name: ")
        
        if usr is None:
            print("\n Not Valid Choice Try again")
        else:
            print ("""
    1.CSV
    2.TXT
    """)            
            fileType = input("CSV OR TXT?")
            if fileType == "1" or fileType == "2":
                userInformation(usr, fileType)
                
            elif ans !="":
                print("\n Not Valid Choice Try again")
    elif ans=="4":
        ip = input("Enter IP Address: ") 
        if ip is None:
            print("\n Not Valid Choice Try again")
        else:
            print ("""
    1.CSV
    2.TXT
    """)
            fileType = input("CSV OR TXT?")
            if fileType == "1" or fileType == "2":
                ipInformation(ip, fileType)
                
            elif ans !="":
                print("\n Not Valid Choice Try again")            
    elif ans=="5":
        threshold = input("Enter threshold for search: ") 
        if threshold is None:
            print("\n Not Valid Choice Try again")    
        try:        
            val = int(threshold)  
            print ("""
            1.ips
            2.usernames
            3.cities
            4.countries
            5.times
            6.deviceTypes
            7.macaddresses
            """)            
            arrChoice = input("Which data would you like to find repeating information: ")
            
            
            if arrChoice == "1" or arrChoice == "2" or arrChoice == "3" or arrChoice == "4" or arrChoice == "5" or arrChoice == "6" or arrChoice == "7":
                print ("""
        1.CSV
        2.TXT
        """)                
                ans2 = input("CSV OR TXT?")
                if ans2 == "1" or ans2 == "2":
                    ans3 = input("Please Enter Name of File: ")
                    if ans3 != "":
                        repeatingIps(threshold, arrChoice, ans2, ans3)
                    elif ans !="":
                        print("\n Not Valid Choice Try again")                    
                elif ans2 != "":
                    print("\n Not Valid Choice Try again")
                 
            elif arrChoice !="":
                
                print("\n Not Valid Choice Try again")            
        except ValueError:
            print("Not a valid input")        
        
        

    elif ans=="6":
        print("This function can be useful for loading previous data into new or just combining other information")
        print("This function requires .txt files")
        print("Please note if your combining two files for input, they will need to strictly be in same format")
        ans3 = input("Please Enter Name of File 1 to combine into: ")
        
        if ans3 != "":
            ans4 = input("Please Enter Name of File 2 to combine into: ")
            if ans4 != "":
                ans5 = input("Please Enter Name of file to output to: ")
                if ans5 != "":
                    combineFiles(ans3, ans4, ans5)
    elif ans=="7":
        blackList()
        print("\n EMPT") 
    elif ans=="8":
        print("Quick Scan:")
        print("Quick Scan will report users/ips that may be at risk intelligently as well as providing a reason why")
        ans3 = input("Please Enter Name of File: ")
        if ans3 != "":
            print ("""
    1.CSV
    2.TXT
    """)            
            fileType = input("CSV OR TXT?")
            if fileType == "1" or fileType == "2":            
                testUnique(usernames)
                quickScan(fileType, ans3, checked)
    elif ans=="9":
        print ("""
1.Usage of IPS
2.Usage of Users
""")        
        ans2 = input("IPS or Users: ")
        if ans2 == "1" or ans2 == "2":
            print ("""
        1.CSV
        2.TXT
        """)
            ans3 = input("CSV OR TXT?")
            if ans3 == "1" or ans3 == "2":
                ans4 = input("Please Enter Name of File: ")
                
                if ans4 != "" and ans2 == "1":
                    sumofusage2(ans3,ans4)
                elif ans4 != "" and ans2 == "2":
                    sumofusage(ans3,ans4)
                
    elif ans=="10":
     
        if savetest is True:
            print("WARNING: you have already used this function this load, performing it again will duplicate save data")
            ans2 = input("Are you sure you want to do this?(Y/N)")
            if ans2 == "Y":
               
                saveInformation()
                print("Saved")
            else:
                print("Exiting..")
                time.sleep(2)
                exit()
        else:
            
            saveInformation()
            print("Saved")
            savetest = True            
        
    elif ans=="11":
        print("Please Note: This loads any data saved in the savedata folder. Please ensure you are not loading duplicate data as this will have duplicate results.")
        anso = input("Press any key to continue.")
        print("Loading")
        loadInformation()

    elif ans == "12":
        ans4 = input("Please Enter Name of File: ")
        if ans4 != "":
            threshold = input("Enter threshold for search: ") 
            if threshold is not None:
                val = int(threshold)
                print ("""
        1.Top X User Failed Logins
        2.Top X IP Failed Logins
        3.Top X IP Failed Logins(NO US)
        """)
                ans2 = input("Choose Option: ")
                if ans2 == "1":
                    topXuserFailed("1", ans4, val)
                if ans2 == "2":
                    topXipFailed("1", ans4, val)
                if ans2 == "3":
                    topXipFailedNoUs("1", ans4, val)
                else:
                    print("Not valid choice")
            else:
                print("\n Not Valid Choice Try again")    
   
           
    elif ans == "13":
        print("Exiting...")
        time.sleep(2)
        exit()    
        
        
    elif ans !="":
        print("\n Not Valid Choice Try again") 
 

