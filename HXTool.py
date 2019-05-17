# -*- coding: utf-8 -*-
"""
Created on Fri Mar  9 13:22:07 2018
Updated on Thu May 9
@author: Kiranraj(kjogleka), Himanshu(hsardana), Komal(kpanzade), Avinash(avshukla)
"""
import subprocess
import paramiko
import threading
import time
import datetime
import logging 
import sys
import os
import shutil
import getpass
import re
from prettytable import PrettyTable, ALL
from collections import OrderedDict
from progressbar import ProgressBarThread
from multiprocessing import Process


########################       Logger        #################################
INFO = logging.INFO
DEBUG = logging.DEBUG
ERROR = logging.ERROR

def get_date_time():
    return (datetime.datetime.now().strftime("%d-%m-%Y_%I-%M-%S %p"))

def log_start(log_file, log_name, lvl):
    # Create a folder
    cdate = datetime.datetime.now()
    dir_name = "HX_Report_" + str(cdate.strftime("%d_%m_%Y_%H_%M"))
    try:
        os.makedirs(dir_name)
    except FileExistsError:
        shutil.rmtree(dir_name)
        os.makedirs(dir_name)
    os.chdir(dir_name)
    # Configure logger file handler
    global logger
    log_level = lvl
    logger = logging.getLogger(log_name)
    logger.setLevel(log_level)
    
    # Create a file handler
    handler = logging.FileHandler(log_file)
    handler.setLevel(log_level)
    
    # Create a logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%m-%d-%Y %I:%M:%S %p')
    handler.setFormatter(formatter)
    
    # Add the handlers to the logger
    logger.addHandler(handler)
    msg = "HX Checkup Tool Started at Date/Time :" + get_date_time().replace("_", "/") + "\r"
    global start_time
    start_time = datetime.datetime.now()
    logger.info(msg)
    #log_msg("", msg)
    logger.info("Logger Initialized\r")

def log_stop():
    # Shutdown the logger handler
    #log_msg(INFO, "Shutdown the logger")
    logging.shutdown()
    
def log_entry(cmd_name):
    # Each function will call this in the beginning to enter any DEBUG info
    logger.log(DEBUG, 'Entered command :' + cmd_name + "\r")
    
def log_exit(cmd_name):
    # Each function will call this in the end, to enter any DEBUG info
    logger.log(DEBUG, 'Exited command :' + cmd_name + "\r")
    
def log_msg(lvl, *msgs):
    # Each function will call this to enter any INFO msg
    msg = ""
    if len(msgs)>1:
        for i in msgs:
            msg = msg + str(i) + "\r\n"
        msg.rstrip("\r\n")
    else:
        for i in msgs:
            msg = msg + str(i)
    # Print on Console & log
    for line in msg.split("\r\n"):
        if lvl == "" and line != "":
            print(line)
        elif line != "":
            logger.log(lvl, line)
            
def sys_exit(val):
    # Exit the logger and stop the script, used for traceback error handling
    log_msg(INFO, "Closing logger and exiting the application\r")
    msg = "HX Checkup Tool Stopped at Date/Time :" + get_date_time().replace("_", "/") + "\r"
    log_msg(INFO, msg)
    end_time = datetime.datetime.now()
    time_diff = end_time - start_time
    msg = "Test duration: " + str(time_diff.seconds) + " seconds"
    log_msg(INFO, msg)
    #log_msg("", msg)
    log_stop()
    sys.exit(val)     

####################           SSH connection            #####################

def runcmd(cmd):
    # Execute local shell command
    log_entry(cmd)
    log_msg(INFO, "$" * 61 + "\r")
    log_msg(INFO, "\r\nExecuting Shell command: " + cmd + "\r")
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    cmdoutput, err = p.communicate()
    p_status = p.wait()
    output = cmdoutput.split("\n")
    log_msg(INFO, "*" * 24 + " CMD OUTPUT " + "*" * 24 + "\r")
    for line in output:
        log_msg(INFO, str(line) + "\r")
    log_msg(INFO, "*" * 61 + "\r")
    return cmdoutput


def execmd(cmd):
    # Execute command 
    log_entry(cmd)
    log_msg(INFO, "#" * 61 + "\r")
    log_msg(INFO, "\r\nExecuting command: " + cmd + "\r")
    stdin, stdout, stderr = client.exec_command(cmd)
    while not stdout.channel.exit_status_ready():
        time.sleep(1)
    response = stdout.channel.exit_status
    output = []
    if response == 0:
        for line in stdout:
            output.append(line.strip())
    else:
        for line in stderr:
            output.append(line.strip())
        output.insert(0,"Not able to run the command")
    log_msg(INFO, "*"*24 + " CMD OUTPUT " + "*"*24 + "\r")
    for line in output:
        log_msg(INFO, line +"\r")
    log_msg(INFO, "*" * 61 + "\r")
    log_exit(cmd)
    return output

def thread_geteth0ip(ip, hxusername, hxpassword, time_out):
    try:
        # Initiate SSH Connection
        client.connect(hostname=ip, username=hxusername, password=hxpassword, timeout=time_out)
        msg = "\r\nSSH connection established to HX Cluster: " + ip + "\r"
        log_msg(INFO, msg)
        #log_msg("", msg)
        cmd = "hostname -i"
        hxip = execmd(cmd)
        hxips.extend(hxip)
        client.close()
    except Exception as e:
        msg = "\r\nNot able to establish SSH connection to HX Cluster: " + ip + "\r"
        log_msg(INFO, msg)
        log_msg("", msg)
        log_msg(ERROR, str(e) + "\r")

def thread_sshconnect(ip, hxusername, hxpassword, time_out):
    hostd[str(ip)] = dict.fromkeys(["hostname", "date", "ntp source", "eth1", "esxip" "vmk0", "vmk1"], "")
    try:
        # Initiate SSH Connection
        client.connect(hostname=ip, username=hxusername, password=hxpassword, timeout=time_out)
        msg = "\r\nSSH connection established to HX Cluster: " + ip + "\r"
        log_msg(INFO, msg)
        log_msg("", msg)
        # Check hostname
        try:
            cmd = "hostname"
            hname = execmd(cmd)
            hostd[ip]["hostname"] = ("".join(hname)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e) + "\r")
        # Check date
        try:
            cmd = 'date "+%D %T"'
            hdate = execmd(cmd)
            hostd[ip]["date"] = ("".join(hdate)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e) + "\r")
        # Check NTP source
        try:
            cmd = "stcli services ntp show"
            hntp = execmd(cmd)
            hostd[ip]["ntp source"] = ("".join(hntp)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e) + "\r")
        # Get eth1 IP Address
        try:
            cmd = "ifconfig eth1 | grep 'inet addr:' | cut -d: -f2| cut -d' ' -f1"
            eth1ip = execmd(cmd)
            hostd[ip]["eth1"] = ("".join(eth1ip)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e) + "\r")
        # Get vmk0 and vmk1 IP Address
        try:
            #cmd = "/usr/share/springpath/storfs-misc/run-on-esxi.sh 'esxcfg-vmknic -l'"
            # Get ESX IP
            cmd = "/opt/springpath/storfs-mgmt-cli/getLocalNode.sh | grep 'esxiIP=' | cut -d= -f2"
            op = execmd(cmd)
            if op:
                esxip = op[0]
                hostd[ip]["esxip"] = str(esxip)
            """
            for line in op:
                if "vmk0" in line and "IPv4" in line:
                    m = re.search(r"([\d]{1,3}(.[\d]{1,3}){3})", line)
                    if m:
                        hostd[ip]["vmk0"] = str(m.group(1))
                elif "vmk1" in line and "IPv4" in line:
                    m = re.search(r"([\d]{1,3}(.[\d]{1,3}){3})", line)
                    if m:
                        hostd[ip]["vmk1"] = str(m.group(1))
                    break
            """
        except Exception as e:
            log_msg(ERROR, str(e) + "\r")
    except Exception as e:
        msg = "\r\nNot able to establish SSH connection to HX Cluster: " + ip + "\r"
        log_msg(INFO, msg)
        log_msg("", msg)
        log_msg(ERROR, str(e) + "\r")
    finally:
        client.close()

def get_vmk1(ip, hxusername, esxpassword, time_out):
    esxip = hostd[ip]["esxip"]
    if esxip != "":
        try:
            # Initiate SSH Connection
            client.connect(hostname=esxip, username=hxusername, password=esxpassword, timeout=time_out)
            msg = "\r\nSSH connection established to ESX Host: " + esxip + "\r"
            log_msg(INFO, msg)
            log_msg("", msg)
            # Get vmk0 and vmk1 IP Address
            try:
                cmd = "esxcfg-vmknic -l"
                op = execmd(cmd)
                for line in op:
                    if "vmk0" in line and "IPv4" in line:
                        m = re.search(r"([\d]{1,3}(.[\d]{1,3}){3})", line)
                        if m:
                            hostd[ip]["vmk0"] = str(m.group(1))
                    elif "vmk1" in line and "IPv4" in line:
                        m = re.search(r"([\d]{1,3}(.[\d]{1,3}){3})", line)
                        if m:
                            hostd[ip]["vmk1"] = str(m.group(1))
                        break
            except Exception as e:
                log_msg(ERROR, str(e) + "\r")
        except Exception as e:
            msg = "\r\nNot able to establish SSH connection to ESX Host: " + esxip + "\r"
            log_msg(INFO, msg)
            log_msg("", msg)
            log_msg(ERROR, str(e) + "\r")
        finally:
            client.close()

def cluster_services_check(ip):
    # 1) stcli cluster info
    cldict = {}
    # Get Healthstate
    cmd = "stcli cluster info | grep -i healthState: | cut -d: -f2"
    op = execmd(cmd)
    cldict["HealthState"] = "".join(op)
    # Get State
    cmd = "stcli cluster info | grep -i ^State: | cut -d: -f2"
    op = execmd(cmd)
    cldict["State"] = "".join(op)
    log_msg(INFO, str(cldict) + "\r")

    # 2) sysmtool --ns cluster --cmd healthdetail
    cmd = "sysmtool --ns cluster --cmd healthdetail"
    cl_health = execmd(cmd)
    cl_health_reason = []
    flag2 = flag3 = flag4 = 0  
    global nodes
    nodes = ""
    for line in cl_health:
        if line.startswith("Cluster Health Detail:"):
            flag2 = 1
            continue
        if flag2 == 1 and line.startswith("State:"):
            s = str(line.split(": ")[-1]).lower()
            if cldict["State"] == s :
                pass
            else:
                cldict["State"] = s
            continue
        if flag2 == 1 and "HealthState:" in line:
            h = str(line.split(": ")[-1]).lower()
            if cldict["HealthState"] == h:
                continue
            else:
                cldict["HealthState"] = h
                flag3 = 1
        if flag3 == 1 and "Health State Reason:" in line:
            flag4 = 1
            continue
        if flag4 == 1:
            if not line.startswith("#"):
                break
            else:
                cl_health_reason.append(line)
        if flag2 == 1 and "Current ensemble size:" in line:
            nodes = line.strip().split(": ")[1]
            break
    log_msg(INFO, str(cldict) + "\r")
    hostd[ip].update(cldict)

    # 3) service_status.sh 
    cmd = "service_status.sh"
    cl_service = execmd(cmd)
    # pidof storfs
    cmd = "pidof storfs"
    op = execmd(cmd)
    for line in op:
        s = line.strip()
        if s.isdigit():
            cl_service.append("storfs {:>44}".format("... Running"))
        else:
            cl_service.append("storfs {:>44}".format("... Not Running"))   
    # pidof stMgr
    cmd = "pidof stMgr"
    op = execmd(cmd)
    for line in op:
        s = line.strip()
        if s.isdigit():
            cl_service.append("stMgr {:>45}".format("... Running"))
        else:
            cl_service.append("stMgr {:>45}".format("... Not Running"))
    # pidof stNodeMgr
    cmd = "pidof stNodeMgr"
    op = execmd(cmd)
    for line in op:
        s = line.strip()
        if s.isdigit():
            cl_service.append("stNodeMgr {:>41}".format("... Running"))
        else:
            cl_service.append("stNodeMgr {:>41}".format("... Not Running"))  
    
    # 4) sysmtool --ns cluster --cmd enospcinfo
    cmd = "sysmtool --ns cluster --cmd enospcinfo"
    cl_space = execmd(cmd)
    free_capacity = ""
    ENOSPC_warning = ""
    space_state = ""
    enospc_state = ""
    enospc_state_check = "FAIL"
    for line in cl_space:
        if "Free capacity:" in line:
            free_capacity = line.strip().split(": ")[1]
        if "ENOSPC warning:" in line:
            ENOSPC_warning = line.strip().split(": ")[1]
    if free_capacity[-1] == ENOSPC_warning[-1]:
        if float(free_capacity[:-1])>= float(ENOSPC_warning[:-1]):
            space_state = "healthy"
        else:
            space_state = "unhealthy"
    elif free_capacity[-1] == "T":
        if (float(free_capacity[:-1])*1024)>= float(ENOSPC_warning[:-1]):
            space_state = "healthy"
        else:
            space_state = "unhealthy"
    elif free_capacity[-1] == "G":
        if (float(free_capacity[:-1])*1024)>= float(ENOSPC_warning[:-1]):
            space_state = "healthy"
        else:
            space_state = "unhealthy"
    elif free_capacity[-1] == "M":
        if (float(free_capacity[:-1])*1024*1024)>= float(ENOSPC_warning[:-1]):
            space_state = "healthy"
        else:
            space_state = "unhealthy"
    for line in cl_space:
        if "Enospc state:" in line:
            l = line.split(": ")
            if len(l) == 2:
                enospc_state = l[1]
                if "ENOSPACE_CLEAR" in enospc_state.strip():
                    enospc_state_check = "PASS"
            break
    # 5) stcli cleaner info
    cmd = "stcli cleaner info"
    clop = execmd(cmd)
    cl_cleaner_state = ""
    # Get eth1 ip address
    cmd = "ifconfig eth1 | grep 'inet addr:' | cut -d: -f2| cut -d' ' -f1"
    op = execmd(cmd)
    eth1ip = ""
    if op:
        eth1ip = op[0]
    for line in clop:
        if eth1ip in line or ip in line:
            if "online" in line.lower():
                cl_cleaner_state = "online"
            elif "offline" in line.lower():
                cl_cleaner_state = "offline"
            break
    # 6) Data Replication Factor
    cmd = "stcli cluster info | grep 'dataReplicationFactor:' | tail -1 | cut -d: -f2"
    op = execmd(cmd)
    rf = ""
    if op:
        rf = op[0].strip()
    # Update Test Detail info
    testdetail[ip]["Cluster services check"] = OrderedDict()
    # State
    testdetail[ip]["Cluster services check"]["State"] = cldict["State"]
    # HealthState
    testdetail[ip]["Cluster services check"]["HealthState"] = cldict["HealthState"]
    # Services
    testdetail[ip]["Cluster services check"]["Services"] = cl_service
    # Space state
    testdetail[ip]["Cluster services check"]["Space State"] = space_state
    # Enospc state
    testdetail[ip]["Cluster services check"]["Enospc State"] = enospc_state
    # Cleaner state
    testdetail[ip]["Cluster services check"]["Cleaner Info"] = cl_cleaner_state
    # Data Replication Factor
    testdetail[ip]["Cluster services check"]["Replication Factor"] = rf

    # Update Test summary
    cluster_service_chk = "FAIL"
    if cldict["State"] == "online":
        cluster_service_chk = "PASS"
    if cldict["HealthState"] == "healthy":
        cluster_service_chk = "PASS"
    for line in cl_service:
        if "Springpath File System" in line and "Not" in line:
            cluster_service_chk = "FAIL"
            break
        elif "SCVM Client" in line and "Not" in line:
            cluster_service_chk = "FAIL"
            break
        elif "System Management Service" in line and "Not" in line:
            cluster_service_chk = "FAIL"
            break
        elif line.startswith("Cluster IP Monitor") and "Not" in line:
            cluster_service_chk = "FAIL"
            break
    testsum[ip].update({"Cluster services check": cluster_service_chk})
    testsum[ip].update({"Enospc state check": enospc_state_check})
    
def zookeeper_check(ip):
    # ZooKeeper and Exhibitor check
    # echo srvr | nc localhost 2181
    cmd = "echo srvr | nc localhost 2181"
    zkl = execmd(cmd)
    mode = ""
    for line in zkl:
        if "Mode:" in line:
            mode = line.split(": ")[1]
    
    # pidof exhibitor
    cmd = "pidof exhibitor"
    exhl = execmd(cmd)
    exh_service = ""
    exh_comm = []
    zcond1 = 0
    for line in exhl:
        s = line.strip()
        if s.isdigit():
            exh_service = "exhibitor {:>32}".format("... Running")
        else:
            exh_service = "exhibitor {:>32}".format("... Not Running")
            zcond1 = 1    
    if zcond1 == 1:
        cmd = "ls /etc/springpath/*"
        op = execmd(cmd)
        exh_comm.append("Files in the path[/etc/springpath/*]") 
        for line in op:
            exh_comm.append(line.strip()) 
        cmd = "ls /opt/springpath/config/*"
        op = execmd(cmd)
        exh_comm.append("\nFiles in the path[/opt/springpath/config/*]") 
        for line in op:
            exh_comm.append(line.strip())    
            
    # ls /etc/exhibitor/exhibitor.properties
    cmd = "ls /etc/exhibitor/exhibitor.properties"
    op = execmd(cmd)
    prop_file = ""
    for line in op:
        if "exhibitor.properties" in line:
            prop_file = "Exists"
        else:
            prop_file = "Not Exists"
    # Epoch Issue
    cmd = 'grep -m1 "" /var/zookeeper/version-2/acceptedEpoch'
    op = execmd(cmd)
    accepoch = "".join(op)
    cmd = 'grep -m1 "" /var/zookeeper/version-2/currentEpoch'
    op = execmd(cmd)
    curepoch = "".join(op)

    # Update Test Detail info
    testdetail[ip]["ZooKeeper and Exhibitor check"] = OrderedDict()
    # Mode
    testdetail[ip]["ZooKeeper and Exhibitor check"]["Mode"] = mode

    # Current ensemble size
    testdetail[ip]["ZooKeeper and Exhibitor check"]["Current ensemble size"] = nodes

    # Services
    testdetail[ip]["ZooKeeper and Exhibitor check"]["Services"] = exh_service

    # exhibitor.properties file
    testdetail[ip]["ZooKeeper and Exhibitor check"]["exhibitor.properties file"] = prop_file

    # Accepted Epoch value
    testdetail[ip]["ZooKeeper and Exhibitor check"]["Accepted Epoch value"] = accepoch

    # Current Epoch value
    testdetail[ip]["ZooKeeper and Exhibitor check"]["Current Epoch value"] = curepoch


    # Update Test summary
    zoo_chk = "FAIL"
    exh_chk = "FAIL"
    if mode == "follower" or mode == "leader" or mode == "standalone":
        zoo_chk = "PASS"
    if "running" in exh_service.lower():
        exh_chk = "PASS"
    testsum[ip].update({"Zookeeper check": zoo_chk})
    testsum[ip].update({"Exhibitor check": exh_chk})
    
def hdd_check(ip):
    # HDD health check
    # sysmtool --ns disk --cmd list
    # sysmtool --ns disk --cmd list | grep -i claimed | wc -l
    # Claimed Disks
    cmd = "sysmtool --ns disk --cmd list | grep -i claimed | wc -l"
    op = execmd(cmd)
    cdsk = ""
    for line in op:
        cdsk = line.strip()
    # sysmtool --ns disk --cmd list | grep -i blacklisted | wc -l
    # Blacklisted Disks
    cmd = "sysmtool --ns disk --cmd list | grep -i blacklisted | wc -l"
    op = execmd(cmd)
    bdsk = ""
    for line in op:
        bdsk = line.strip()
    if bdsk != "":
        cmd = "sysmtool --ns disk --cmd list"
        opl = execmd(cmd)
        flg1 = flg2 = 0
        bdisklist = []
        for line in opl:
            if "UUID:" in line:
                flg1 = 1
                flg2 = 0
                continue
            if flg1 == 1 and "State:" in line and "BLACKLISTED" in line:
                flg2 = 1
                flg1 = 0
                continue
            if flg2 == 1 and "Path:" in line:
                ln = line.split(": ")
                if len(ln) == 2:
                    bdisklist.append(ln[1])
        logger.info("Blacklisted Disks: " + ",".join(bdisklist) + "\r")
    # sysmtool --ns disk --cmd list | grep -i ignored | wc -l
    # Ignored Disks
    cmd = "sysmtool --ns disk --cmd list | grep -i ignored | wc -l"
    op = execmd(cmd)
    idsk = ""
    for line in op:
        idsk = line.strip()
    # Update Test Detail info
    testdetail[ip]["HDD health check"] = OrderedDict()
    # Claimed
    testdetail[ip]["HDD health check"]["Claimed"] = cdsk

    #Blacklisted
    testdetail[ip]["HDD health check"]["Blacklisted"] = {"Status": bdsk, "Result": "\n".join(bdisklist)}

    # Ignored
    testdetail[ip]["HDD health check"]["Ignored"] = idsk

    # Update Test summary
    hd_chk = "PASS"
    if int(bdsk) > int(cdsk):
        hd_chk = "FAIL"
    testsum[ip].update({"HDD health check": hd_chk})

# Pre-Upgrade Check
def pre_upgrade_check(ip):
    # 1) Check HX Cluster version
    cmd = "stcli cluster version"
    hxvs = execmd(cmd)
    # 2) NTP deamon running check
    ntp_deamon_check = "FAIL"
    cmd = "ps aux | grep ntp"
    ntp_deamon = ""
    op = execmd(cmd)
    for line in op:
        match = re.search(r"^ntp \s+\d+", line)
        if match:
            ntp_deamon = match.group()
            ntp_deamon_check = "PASS"
            msg = "\r\nNTP deamon running check: " + str(ntp_deamon) + "\r"
            log_msg(INFO, msg)
            #print(match.group())
    # 3) NTP Sync Check
    cmd = "ntpq -p -4"
    ntpsl = execmd(cmd)
    ntp_sync_check = "FAIL"
    ntp_sync_line = ""
    flag1 = 0
    for line in ntpsl:
        if "======" in line:
            flag1 = 1
            continue
        if flag1 == 1:
            msg = "\r\nNTP sync check: " + str(line) + "\r"
            log_msg(INFO, msg)
            l = line.split()
            ntp_sync_line = l[0]
            if line.startswith("*"):
                ntp_sync_check = "PASS"
            break

    # 3) DNS check
    cmd = "stcli services dns show"
    op = execmd(cmd)
    dnsip = ""
    dns_check = "FAIL"
    for line in op:
        match = re.search(r"(?:\d{1,3}.){3}\d{1,3}", line)
        if match:
           dnsip = match.group()
           msg = "\r\nDNS IP Address: " + str(dnsip) + "\r"
           log_msg(INFO, msg)
    if dnsip:
        cmd = "ping {} -c 3 -i 0.01".format(dnsip)
        op = execmd(cmd)
        for line in op:
            if "0% packet loss" in line:
                dns_check = "PASS"
                break
    # Update Test summary
    testsum[ip].update({"DNS check": dns_check})
    # 4) vCenter Reachability check
    cmd = "stcli cluster info | grep vCenterURL"
    op = execmd(cmd)
    vcenterip = ""
    vcenter_check = "FAIL"
    for line in op:
        match = re.search(r"(?:\d{1,3}.){3}\d{1,3}", line)
        if match:
           vcenterip = match.group()
           msg = "\r\nvCenter IP Address: " + str(vcenterip) + "\r"
           log_msg(INFO, msg)
        else:
            try:
                l = line.split(":")
                if len(l) == 2:
                    dnip = l[1]
                    vcenterip = dnip.strip()
                    msg = "\r\nvCenter IP Address: " + str(vcenterip) + "\r"
                    log_msg(INFO, msg)
            except Exception:
                pass

    if vcenterip:
        cmd = "ping {} -c 3 -i 0.01".format(vcenterip)
        op = execmd(cmd)
        for line in op:
            if "0% packet loss" in line:
                vcenter_check = "PASS"
                break
    # Update Test summary
    testsum[ip].update({"vCenter reachability check": vcenter_check})
    testsum[ip].update({"Timestamp check": str(hostd[ip]["date check"])})
    if ntp_deamon_check == "PASS" and hostd[ip]["ntp source check"] == "PASS" and ntp_sync_check == "PASS":
        testsum[ip].update({"NTP sync check": "PASS"})
    else:
        testsum[ip].update({"NTP sync check": "FAIL"})
    # 5) Check cluster usage
    cmd = "stcli cluster storage-summary | grep -i nodeFailuresTolerable"
    op = execmd(cmd)
    op = "".join(op)
    op = op.strip()
    NFT = op.split(":")[1]
    cmd = "stcli cluster storage-summary | grep -i cachingDeviceFailuresTolerable"
    op = execmd(cmd)
    op = "".join(op)
    op = op.strip()
    HFT = op.split(":")[1]
    cmd = "stcli cluster storage-summary | grep -i persistentDeviceFailuresTolerable"
    op = execmd(cmd)
    op = "".join(op)
    op = op.strip()
    SFT = op.split(":")[1]

    # 6) Check cache is spread across all controller
    cmd = "nfstool -- -m | sort -u -k2"
    cachl = []
    op = execmd(cmd)
    for line in op:
        m = re.search(r"^\d+\s+([\d]{1,3}(.[\d]{1,3}){3})", line)
        if m:
            cachl.append(str(m.group(1)))
    #print(cachl)

    # 7) Cluster Upgrade status
    cmd = "stcli cluster upgrade-status"
    upst = "PASS"
    op = execmd(cmd)
    for line in op:
        if "exception" in line or "Not able to run the command" in line:
            upst = "FAIL"
            break
    # Update Test summary
    testsum[ip].update({"Cluster upgrade status": upst})
    # 8) Check any extra number of pnodes
    cmd = "stcli cluster info | grep -i  pnode -n2 | grep -i name | wc -l"
    op = execmd(cmd)
    op = "".join(op)
    pnodes = int(op)
    #cmd = "stcli cluster info | grep -i  stctl_mgmt -n1 | grep -i addr | wc -l"
    #op = execmd(cmd)
    #op = "".join(op)
    snodes = len(eth1_list)
    nodecheck = "FAIL"
    if pnodes == snodes:
        nodecheck = "PASS"
    testsum[ip].update({"Extra pnodes check": nodecheck})
    # 9) Check Disk usage(/var/stv)
    cmd = "df -h | grep -i /var/stv"
    dskusg = ""
    dskst  = ""
    op = execmd(cmd)
    for line in op:
        m = re.search(r"(\d+)%", line)
        if m:
            dskusg = m.group(1)
            if int(dskusg) <= 80 :
                dskst = "Good"
                testsum[ip].update({"Disk usage(/var/stv) check": "PASS"})
            else:
                dskst = "Bad"
                testsum[ip].update({"Disk usage(/var/stv) check": "FAIL"})
    # 10) check packages and versions
    cmd = "dpkg -l | grep -i spring"
    op = execmd(cmd)
    check_package_version = []
    for line in op:
        check_package_version.append(line.replace(" " * 26, "    "))
    # check memory
    cmd = "free -m"
    check_memory = execmd(cmd)
    # check CPU
    cmd = "top -b -n 1 | grep -B7 KiB"
    check_cpu = execmd(cmd)
    if not check_cpu:
        cmd = "top -b -n 1 | grep Cpu"
        check_cpu = execmd(cmd)
    # check Out of memory
    #cmd = "cat /var/log/kern.log | grep -i 'out of memory' -A5"
    cmd = "grep -i 'out of memory' -A5 /var/log/kern.log"
    op = execmd(cmd)
    if "Not able to run the command" in op:
        check_oom = ["No issue"]
        testsum[ip].update({"Out of memory check": "PASS"})
    else:
        check_oom = op
        testsum[ip].update({"Out of memory check": "FAIL"})
    # ESXi supported upgrade
    cmd = "grep -i ^esxi.version /usr/share/springpath/storfs-fw/springpath-hcl.conf"
    op = execmd(cmd)
    svsp = []
    if op:
        for line in op:
            if "esxi.version=" in line:
                l = line.split("=")
                if len(l) == 2:
                    vl = l[1]
                    svsp = vl.split(",")
    testsum[ip].update({"Supported vSphere versions": str("\n".join(svsp))})
    ######################
    # Update Test Detail info
    testdetail[ip]["Pre-Upgrade check"] = OrderedDict()
    # HX Cluster version
    testdetail[ip]["Pre-Upgrade check"]["HX Cluster version"] = hxvs
    # NTP deamon running
    testdetail[ip]["Pre-Upgrade check"]["NTP deamon running"] = {"Status": ntp_deamon, "Result": ntp_deamon_check}
    # NTP sync check
    testdetail[ip]["Pre-Upgrade check"]["NTP sync check"] = {"Status": ntp_sync_line, "Result": ntp_sync_check}
    # DNS check
    testdetail[ip]["Pre-Upgrade check"]["DNS check"] = {"Status": dnsip, "Result": dns_check}
    # vCenter reachability check
    testdetail[ip]["Pre-Upgrade check"]["vCenter reachability check"] = {"Status": vcenterip, "Result": vcenter_check}
    # Timestamp check
    allhostdt = []
    for i in sorted(hostd.keys()):
        allhostdt.append(str(i) + " - " + str(hostd[i]["date"]))
    testdetail[ip]["Pre-Upgrade check"]["Timestamp check"] = {"Status": str("\n".join(allhostdt)), "Result": str(hostd[ip]["date check"])}
    # Primary NTP Source check
    allntpsrc = []
    for p in sorted(hostd.keys()):
        allntpsrc.append(str(p) + " : NTP IP - " + str(hostd[p]["ntp source"]))
    testdetail[ip]["Pre-Upgrade check"]["Primary NTP Source check"] = {"Status": str("\n".join(allntpsrc)), "Result": str(hostd[ip]["ntp source check"])}
    # Cluster usage
    testdetail[ip]["Pre-Upgrade check"]["Cluster Fault Tolerance"] = "Node Failures Tolerable:" + str(NFT) + "\nHDD Failures Tolerable:" + str(HFT) + "\nSSD Failures Tolerable:" + str(SFT)
    # Cache usage
    testdetail[ip]["Pre-Upgrade check"]["Cache vNodes"] = str("\n".join(cachl))
    # Cluster Upgrade
    testdetail[ip]["Pre-Upgrade check"]["Cluster Upgrade Status"] = upst
    # No extra pnodes
    testdetail[ip]["Pre-Upgrade check"]["No extra pnodes"] = nodecheck
    # Disk usage(/var/stv)
    testdetail[ip]["Pre-Upgrade check"]["Disk usage(/var/stv)"] = {"Status": str(dskusg) + "%", "Result": dskst}
    # Check package & versions
    testdetail[ip]["Pre-Upgrade check"]["Check package & versions"] = str("\n".join(check_package_version))
    # Check memory
    testdetail[ip]["Pre-Upgrade check"]["Check memory"] = str("\n".join(check_memory))
    # Check CPU
    testdetail[ip]["Pre-Upgrade check"]["Check CPU"] = str("\n".join(check_cpu))
    # Check Out of memory
    testdetail[ip]["Pre-Upgrade check"]["Check Out of memory"] = str("\n".join(check_oom))
    # Supported vSphere versions
    testdetail[ip]["Pre-Upgrade check"]["Supported vSphere versions"] = str("\n".join(svsp))


def pingstatus(op):
    pgst = "SUCCESS"
    for line in op:
        if "0 packets received" in line:
            pgst = "FAIL"
    return pgst

def network_check(ip):
    try:
        # Close connection
        client.close()
    except Exception:
        pass

    try:
        esxip = hostd[ip]["esxip"]
        if esxip != "":
            # Initiate SSH Connection
            client.connect(hostname=esxip, username=hxusername, password=esxpassword, timeout=time_out)
            msg = "\r\nSSH connection established to ESX Host: " + esxip + "\r"
            log_msg(INFO, msg)
            # log_msg("", msg)
            # Get all ESX and Storage Controller IP Address
            opd = OrderedDict()
            nwtestsum[esxip] = OrderedDict()
            nwtestdetail[esxip] = OrderedDict()
            # Check hx user created
            try:
                cmd = "esxcli system account list"
                op = execmd(cmd)
                hxac = "FAIL"
                for line in op:
                    if "hxuser" in line:
                        hxac = "PASS"
                opd.update({"HX User Account Created": hxac})
            except Exception:
                pass
            # Check vMotion Enabled
            try:
                cmd = "esxcli network firewall ruleset list | grep -i vMotion"
                op = execmd(cmd)
                vmst = "FAIL"
                for line in op:
                    if "vMotion" in line and "true" in line:
                        vmst = "PASS"
                        break
                opd.update({"vMotion Enabled": vmst})
            except Exception:
                pass
            # Check ESXi Version
            try:
                cmd = "vmware -l"
                op = execmd(cmd)
                opd.update({"ESX Version": op})
            except Exception:
                pass
            # ESX vib list
            try:
                cmd = "esxcli software vib list| grep -i spring"
                op = execmd(cmd)
                nop = []
                for line in op:
                    nop.append(line.replace(" "*26, "    "))
                opd.update({"ESX Vib List": nop})
            except Exception:
                pass
            # ESX Services
            try:
                cmd = "chkconfig --list | grep -E 'ntpd|hostd|vpxa|stHypervisorSvc|scvmclient|hxctlvm'"
                op = execmd(cmd)
                opd.update({"ESX Services": op})
            except Exception:
                pass
            # Check for HX down during upgrade
            try:
                cmd = "esxcli system settings advanced list | grep TeamPolicyUpDelay -A2 | grep Int"
                op = execmd(cmd)
                check_HX_down_status = ""
                for line in op:
                    if line.endswith(" 100"):
                        check_HX_down_status = "FAIL"
                    else:
                        check_HX_down_status = "PASS"
                opd["Check for ESXI Failback timer"] = check_HX_down_status
            except Exception:
                pass
            # vmk0 ping to each ESXi
            # vmk0 ping to each ESXi vmk0
            allpingchk = []
            for h in esx_hostsl:
                try:
                    cmd = "vmkping -I {} -c 3 -d -s 1472 -i 0.01 {}".format("vmk0", h)
                    op = execmd(cmd)
                    pst = pingstatus(op)
                    cm = "vmkping -I {} -c 3 -d -s 1472 -i 0.01 {}".format("vmk0", h)
                    opd.update({cm : pst})
                    allpingchk.append(pst)
                except Exception:
                    pass
            # vmk1 ping to each ESXi vmk1
            if len(vmk1_list) > 0 :
                for k in vmk1_list:
                    try:
                        cmd = "vmkping -I {} -c 3 -d -s 8972 -i 0.01 {}'".format("vmk1", k)
                        op = execmd(cmd)
                        pst = pingstatus(op)
                        cm = "vmkping -I {} -c 3 -d -s 8972 -i 0.01 {}".format("vmk1", k)
                        opd.update({cm: pst})
                        allpingchk.append(pst)
                    except Exception:
                        pass
            # vmk0 ping to each SCVM eth0
            if len(hxips) > 0 :
                for h in hxips:
                    try:
                        cmd = "vmkping -I {} -c 3 -d -s 1472 -i 0.01 {}".format("vmk0", h)
                        op = execmd(cmd)
                        pst = pingstatus(op)
                        cm = "vmkping -I {} -c 3 -d -s 1472 -i 0.01 {}".format("vmk0", h)
                        opd.update({cm: pst})
                        allpingchk.append(pst)
                    except Exception:
                        pass
            # vmk1 ping to each SCVM eth1
            if len(eth1_list) > 0 :
                for k in eth1_list:
                    try:
                        cmd = "vmkping -I {} -c 3 -d -s 8972 -i 0.01 {}".format("vmk1", k)
                        op = execmd(cmd)
                        pst = pingstatus(op)
                        cm = "vmkping -I {} -c 3 -d -s 8972 -i 0.01 {}".format("vmk1", k)
                        opd.update({cm: pst})
                        allpingchk.append(pst)
                    except Exception:
                        pass
            # vSwitch info of ESXi
            try:
                cmd = "esxcfg-vswitch -l"
                op = execmd(cmd)
                cm = "esxcfg-vswitch -l"
                opd.update({cm: op})
            except Exception:
                pass
            # Check extra contoller vm folders
            try:
                cmd = "esxcli hardware platform get | grep -i serial"
                op = execmd(cmd)
                op = "".join(op)
                srno = op.split(":")[1]
                cmd = "ls -d /vmfs/volumes/SpringpathDS-" + str(srno.strip())
                op = execmd(cmd)
                op = [x for x in op if x != ""]
                vmfld = "PASS"
                #print(len(op))
                if op:
                    if len(op) > 1:
                        vmfld = "FAIL" + "\nBug: CSCvh99309" + "\ntz: https://techzone.cisco.com/t5/HyperFlex/How-to-fix-stCtlVM-s-duplicate-folder/ta-p/1174364/message-" +"\nrevision/1174364:1"
                opd.update({"No extra controller vm folders": vmfld})
            except Exception:
                pass
            nwtestdetail.update({esxip: opd})
            # Close connection
            client.close()

            # Test summary
            # HX User Account check
            nwtestsum[esxip]["HX User Account check"] = hxac
            # vMotion enabled check
            nwtestsum[esxip]["vMotion enabled check"] = vmst
            # Check for HX down during upgrade
            #nwtestsum[esxip]["Check for HX down during upgrade"] = check_HX_down_status[:4]
            nwtestsum[esxip]["Check for ESXI Failback timer"] = {"Status": check_HX_down_status, "Result": "If Failed, Change the failback timer to 30secs" + "\nesxcli system settings advanced set -o /Net/TeamPolicyUpDelay --int-value 30000"}
            # Check ping to vmk0, eth0, eth1
            if "FAIL" in allpingchk:
                nwtestsum[esxip]["Check ping to vmk0, eth0, eth1"] = "FAIL"
            else:
                nwtestsum[esxip]["Check ping to vmk0, eth0, eth1"] = "PASS"
            # No extra controller vm folders check
            nwtestsum[esxip]["No extra controller vm folders check"] = vmfld[:4]

    except Exception as e:
        msg = "\r\nNot able to establish SSH connection to ESX Host: " + esxip + "\r"
        log_msg(INFO, msg)
        #log_msg("", msg)
        log_msg(ERROR, str(e) + "\r")


def create_sub_report(ip):
    # create HX controller report file
    global subreportfiles
    filename = "HX_Report_" + str(ip) +".txt"
    subreportfiles.append(filename)
    with open(filename, "w") as fh:
        fh.write("\t\t\tHX Controller: " + ip)
        fh.write("\r\n")
        fh.write("#" * 80)
        fh.write("\r\n")
        n = 1
        for cname in testdetail[ip].keys():
            fh.write("\r\n" + str(n) + ") " + cname + ":")
            fh.write("\r\n")
            tw = PrettyTable(hrules=ALL)
            tw.field_names = ["Name", "Status", "Comments"]
            tw.align = "l"
            for k, v in testdetail[ip][cname].items():
                if type(v) == list:
                    tw.add_row([k, "\n".join(v), ""])
                elif type(v) == dict:
                    tw.add_row([k, v["Status"], v["Result"]])
                else:
                    tw.add_row([k, v, ""])
            fh.write((str(tw)).replace("\n", "\r\n"))
            fh.write("\r\n")
            n += 1

    #print("\r\nSub Report File: " + filename)
    log_msg(INFO, "Sub Report File: " + filename + "\r")


def display_result():
    # Display the test results
    if arg == "detail":
        print("")
        for ip in testdetail.keys():
            print("\r\n\t\t\tHX Controller: " + ip)
            print("#"*80)
            n = 1
            for cname in testdetail[ip].keys():
                print("\r\n" + str(n) + ") " + cname)
                td = PrettyTable(hrules=ALL)
                td.field_names = ["Name", "Status", "Comments"]
                td.align = "l"
                for k, v in testdetail[ip][cname].items():
                    if type(v) == list:
                        td.add_row([k, "\n".join(v), ""])
                    elif type(v) == dict:
                        td.add_row([k, v["Status"], v["Result"]])
                    else:
                        td.add_row([k, v, ""])
                print(td)
                time.sleep(5)
                n += 1
        print("\r\n" + "#" * 80)
        print("\r\t\t\tNetwork check:")
        print("\r" + "#" * 80)
        print("\r\nESX vmk0: " + ", ".join(esx_hostsl) + "\r")
        print("\r\nESX vmk1: " + ", ".join(vmk1_list) + "\r")
        print("\r\nSCVM eth0: " + ", ".join(hxips) + "\r")
        print("\r\nSCVM eth1: " + ", ".join(eth1_list) + "\r")
        for eip in nwtestdetail.keys():
            print("\r\nESX Host: " + eip)
            ed = PrettyTable(hrules=ALL)
            ed.field_names = ["Command/Condition", "Response/Status", "Comments"]
            ed.align = "l"
            for k, v in nwtestdetail[eip].items():
                if type(v) == list:
                    ed.add_row([k, "\n".join(v), ""])
                elif type(v) == dict:
                    ed.add_row([k, v["Status"], v["Result"]])
                else:
                    ed.add_row([k, v, ""])
            print(ed)
            time.sleep(5)
        # Bug details table
        print("\n\nBugs Detail:")
        print(bgt)
        time.sleep(5)
    else:
        print("")
        for ip in testsum.keys():
            print("\r\nHX Controller: " + ip)
            print("\rTest Summary:")
            ts = PrettyTable(hrules=ALL)
            ts.field_names = ["Name", "Result", "Comments"]
            ts.align = "l"
            for k, v in testsum[ip].items():
                if type(v) == list:
                    ts.add_row([k, "\n".join(v), ""])
                elif type(v) == dict:
                    ts.add_row([k, v["Status"], v["Result"]])
                else:
                    ts.add_row([k, v, ""])
            print(ts)
        print("\r\n" + "#" * 80)
        print("\r\t\t\tNetwork check:")
        print("\r" + "#" * 80)
        print("\r\nESX vmk0: " + ", ".join(esx_hostsl) + "\r")
        print("\r\nESX vmk1: " + ", ".join(vmk1_list) + "\r")
        print("\r\nSCVM eth0: " + ", ".join(hxips) + "\r")
        print("\r\nSCVM eth1: " + ", ".join(eth1_list) + "\r")
        for eip in nwtestsum.keys():
            print("\r\nESX Host: " + eip)
            es = PrettyTable(hrules=ALL)
            es.field_names = ["Name", "Result", "Comments"]
            es.align = "l"
            for k, v in nwtestsum[eip].items():
                if type(v) == list:
                    es.add_row([k, "\n".join(v), ""])
                elif type(v) == dict:
                    es.add_row([k, v["Status"], v["Result"]])
                else:
                    es.add_row([k, v, ""])
            print(es)


def create_main_report():
    # create main report file
    filename = "HX_Tool_Main_Report.txt"
    with open(filename, "w") as fh:
        fh.write("\t\t\tHX Tool Main Report:")
        fh.write("\r\n")
        fh.write("#" * 80)
        fh.write("\r\n")
        fh.write("HX Cluster Nodes:")
        fh.write("\r\n")
        fh.write((str(ht)).replace("\n", "\r\n"))
        fh.write("\r\n")

    for sfile in subreportfiles:
        with open(sfile, "r") as fh:
            content = fh.read()
        with open(filename, "a") as fh:
            fh.write("#" * 80)
            fh.write("\r\n")
            fh.write(content)

    with open(filename, "a") as fh:
        fh.write("\r\n")
        fh.write("#" * 80)
        fh.write("\r\n\t\t\t Network check:" + "\r")
        fh.write("\r\n")
        fh.write("#" * 80)
        fh.write("\r\n")
        fh.write("vmk0: " + ", ".join(esx_hostsl))
        fh.write("\r\n")
        fh.write("vmk1: " + ", ".join(vmk1_list))
        fh.write("\r\n")
        fh.write("eth0: " + ", ".join(hxips))
        fh.write("\r\n")
        fh.write("eth1: " + ", ".join(eth1_list))
        fh.write("\r\n")
        for host in sorted(nwtestdetail.keys()):
            fh.write("\r\nESX Host: " + host + "\r")
            t4 = PrettyTable(hrules=ALL)
            t4.field_names = ["Command", "Response", "Comments"]
            t4.align = "l"
            for k, v in nwtestdetail[host].items():
                if type(v) == list:
                    t4.add_row([k, "\n".join(v), ""])
                else:
                    t4.add_row([k, v, ""])
            fh.write("\r\n")
            fh.write((str(t4)).replace("\n", "\r\n"))
            fh.write("\r\n")
        fh.write("\r\n")
        fh.write("\r\nBugs Detail:" + "\r\n")
        fh.write((str(bgt)).replace("\n", "\r\n"))
        fh.write("\r\n")
    print("\r\nMain Report File: " + filename)

##############################################################################
#   Main 
##############################################################################    
if __name__ == "__main__":
    # Log file declaration
    log_file = "HX_Tool_" + get_date_time() + ".log"
    log_name = "HX_TOOL"
    log_start(log_file, log_name, INFO)

    #RSA_KEY_FILE = "/etc/ssh/ssh_host_rsa_key"
    # HX Controller parameter
    print("Please enter below info of HX-Cluster:")
    hxusername = "root"
    log_msg(INFO, "Username: " + hxusername + "\r")
    hxpassword = getpass.getpass("Enter the HX-Cluster Root Password: ")
    esxpassword = getpass.getpass("Enter the ESX Root Password: ")
    port = 22
    hostip = ""
    hostpath = ""
    log_msg(INFO, "Port: " + str(port) + "\r")
    time_out = 30 # Number of seconds for timeout
    log_msg(INFO, "Timeout: " + str(time_out) + "\r")
    # Get Host IP Address of eth1
    cmd = "hostname -i"
    op = runcmd(cmd)
    hostip = op.strip()
    log_msg(INFO, "Host IP Address: " + str(hostip) + "\r")
    # Get Host Path
    cmd = "pwd"
    op = runcmd(cmd)
    hostpath = op.strip()
    log_msg(INFO, "Host Path: " + str(hostpath) + "\r")
    # Arguments passed
    global arg
    arg = ""
    if len(sys.argv) > 1:
        try:
            arg = (sys.argv[1]).lower()
            log_msg(INFO, "Argument: " + str(arg) + "\r")
            print("Option: " + str(arg))
        except Exception:
            pass
    # Get Controller Mgmnt IP Addresses
    # Old cmd used to get controller IP Addresses
    # cmd1 = "stcli cluster info | grep -i  stctl_mgmt -n1 | grep -i addr"
    # Get eth1 ips
    cmd = "sysmtool --ns cluster --cmd info | grep -i uuid"
    op = runcmd(cmd)
    if op:
        ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", op)
    if not ips:
        print("HX Cluster IP Addresses are not found")
        sys_exit(0)
    ips.sort(key=lambda ip: map(int, reversed(ip.split('.'))))
    log_msg(INFO, "IP Adresses: " + ", ".join(ips) + "\r")
    global eth1_list
    eth1_list = list(ips)
    eth1_list.sort(key=lambda ip: map(int, reversed(ip.split('.'))))

    # Get all hostnames
    global hostd
    hostd = {}
    subreportfiles = []
    print("")
    #############################################################
    # Get Controller eth0 ips or storage controller ips
    global hxips
    hxips = []
    # Create instance of SSHClient object
    client = paramiko.SSHClient()

    # Automatically add untrusted hosts (Handle SSH Exception for unknown host)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Get all hostnames and HX IP address using threads
    ipthreads = []
    for ip in ips:
        th = threading.Thread(target=thread_geteth0ip, args=(ip, hxusername, hxpassword, time_out,))
        th.start()
        time.sleep(5)
        ipthreads.append(th)

    for t in ipthreads:
        t.join()


    hxips.sort(key=lambda ip: map(int, reversed(ip.split('.'))))
    log_msg(INFO, "HX IP Adresses: " + ", ".join(hxips) + "\r")

    #############################################################
    # Create instance of SSHClient object
    client = paramiko.SSHClient()

    # Automatically add untrusted hosts (Handle SSH Exception for unknown host)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Get all timestamp using threads
    threads = []
    for ip in hxips:
        th = threading.Thread(target=thread_sshconnect, args=(ip, hxusername, hxpassword, time_out,))
        th.start()
        time.sleep(15)
        threads.append(th)

    for t in threads:
        t.join()


    global ht
    ht = PrettyTable(hrules=ALL)
    ht.field_names = ["Nodes", "IP Address", "HostName"]
    ht.align = "l"
    for i, ip in enumerate(hxips):
        ht.add_row([i+1, ip, hostd[ip].get("hostname", "")])
    print("\r\nHX Cluster Nodes:")
    print(ht)
    print("")

    # NTP Date check
    # timestamp should be same on all storage controllers
    dtresult = ""
    for ip in hostd.keys():
        hostd[ip]["date check"] = dtresult
        try:
            d = hostd[ip]["date"]
            if d == "":
                dtresult = "FAIL"
            else:
                ipdt = datetime.datetime.strptime(d, "%m/%d/%y %H:%M:%S")
                for jp in hostd.keys():
                    if ip == jp:
                        continue
                    else:
                        jd = hostd[jp]["date"]
                        if jd == "":
                            dtresult = "FAIL"
                            continue
                        else:
                            jpdt = datetime.datetime.strptime(jd, "%m/%d/%y %H:%M:%S")
                            if ipdt == jpdt:
                                dtresult = "PASS"
                                continue
                            elif ipdt > jpdt:
                                t = (ipdt - jpdt).seconds
                            else:
                                t = (jpdt - ipdt).seconds
                            if t > 120:
                                dtresult = "FAIL"
                                break
                            else:
                                dtresult = "PASS"
            hostd[ip]["date check"] = dtresult
        except Exception:
            continue

    # NTP source ip address check
    # it should be same on all storage controllers
    ntpsrccheck = ""
    for ip in hostd.keys():
        ipntp = hostd[ip]["ntp source"]
        if ipntp == "":
            ntpsrccheck = "FAIL"
        else:
            for jp in hostd.keys():
                if ip == jp:
                    continue
                elif ipntp == hostd[jp]["ntp source"]:
                    ntpsrccheck = "PASS"
                else:
                    ntpsrccheck = "FAIL"
                    break
        hostd[ip].update({"ntp source check": ntpsrccheck})

    # Get ESX IPs, vmk1 ips
    global esx_hostsl
    esx_hostsl = []
    for ip in hostd.keys():
        esxip = hostd[ip]["esxip"]
        if esxip != "":
            esx_hostsl.append(esxip)

    global vmk1_list
    vmk1_list = []
    # Get all vmk1 using threads
    threads = []
    for ip in hostd.keys():
        th = threading.Thread(target=get_vmk1, args=(ip, hxusername, esxpassword, time_out,))
        th.start()
        time.sleep(5)
        threads.append(th)

    for t in threads:
        t.join()

    for ip in hostd.keys():
        vmk1 = hostd[ip]["vmk1"]
        vmk1_list.append(vmk1)

    if esx_hostsl:
        try:
            esx_hostsl.sort(key=lambda ip: map(int, reversed(ip.split('.'))))
        except Exception:
            pass
    if vmk1_list:
        try:
            vmk1_list.sort(key=lambda ip: map(int, reversed(ip.split('.'))))
        except Exception:
            pass
    log_msg(INFO, "Eth1 IP Adresses: " + ", ".join(eth1_list) + "\r")
    log_msg(INFO, "ESX IP Adresses: " + ", ".join(esx_hostsl) + "\r")
    log_msg(INFO, "vmk1 IP Adresses: " + ", ".join(vmk1_list) + "\r")

    # Check the below things on each controller
    nwdetail = OrderedDict()
    cvm = {}
    global testsum
    testsum = OrderedDict()
    global testdetail
    testdetail = OrderedDict()
    global nwtestsum
    nwtestsum = OrderedDict()
    global nwtestdetail
    nwtestdetail = OrderedDict()
    # Bug details table
    bugs = {
        "HX down": "HX cluster goes down during the UCS infra upgrade. This is because of the default failback delay interval(10sec) on ESXi." + "\nDefault Value - 10sec" + "\nModify to - 30sec"
        }
    global bgt
    bgt = PrettyTable(hrules=ALL)
    bgt.field_names = ["Bug", "Description"]
    bgt.align = "l"
    for k, v in bugs.items():
        bgt.add_row([k, v])

    #############################################################
    # Check on all HX Controller
    # Create instance of SSHClient object
    for ip in hxips:
        try:
            print("\r\nHX Controller: " + str(ip))
            # Initiate SSH Connection
            client.connect(hostname=ip, username=hxusername, password=hxpassword, timeout=time_out)
            msg = "\r\nSSH connection established to HX Cluster: " + ip + "\r"
            log_msg(INFO, msg)
            # log_msg("", msg)
            testsum[ip] = OrderedDict()
            testdetail[ip] = OrderedDict()

            # 1. Cluster services check
            # Progressbar
            pbar = ProgressBarThread()
            pbar.start("Cluster services check     ")
            log_msg(INFO, "Progressbar Started" + "\r")
            cluster_services_check(ip)
            # stop progressbar
            pbar.stop("PASS")
            log_msg(INFO, "Progressbar Stopped" + "\r")

            # 2. ZooKeeper and Exhibitor check
            # Progressbar
            pbar = ProgressBarThread()
            pbar.start("ZooKeeper & Exhibitor check")
            log_msg(INFO, "Progressbar Started" + "\r")
            zookeeper_check(ip)
            # stop progressbar
            pbar.stop("PASS")
            log_msg(INFO, "Progressbar Stopped" + "\r")

            # 3. HDD health check
            # Progressbar
            pbar = ProgressBarThread()
            pbar.start("HDD health check           ")
            log_msg(INFO, "Progressbar Started" + "\r")
            hdd_check(ip)
            # stop progressbar
            pbar.stop("PASS")
            log_msg(INFO, "Progressbar Stopped" + "\r")

            # 4. Pre-Upgrade Check
            # Progressbar
            pbar = ProgressBarThread()
            pbar.start("Pre-Upgrade Check          ")
            log_msg(INFO, "Progressbar Started" + "\r")
            pre_upgrade_check(ip)
            # stop progressbar
            pbar.stop("PASS")
            log_msg(INFO, "Progressbar Stopped" + "\r")

            # 5. Network Summary
            # Progressbar

            pbar = ProgressBarThread()
            pbar.start("Network check              ")
            log_msg(INFO, "Progressbar Started" + "\r")
            network_check(ip)
            # stop progressbar
            pbar.stop("PASS")
            log_msg(INFO, "Progressbar Stopped" + "\r")

            # Close connection
            client.close()

            # Create report file
            create_sub_report(ip)

        except Exception as e:
            msg = "\r\nNot able to establish SSH connection to HX Cluster: " + ip + "\r"
            log_msg(INFO, msg)
            #log_msg("", msg)
            log_msg(ERROR, str(e) + "\r")
            # sys_exit(0)
            # stop progressbar
            pbar.stop("FAIL")
            log_msg(INFO, "Progressbar Stopped" + "\r")
            continue

    ###############################################################





    # Display the test result
    display_result()

    # Print Report to file
    create_main_report()
    # End
    sys_exit(0)
###############################################################################
