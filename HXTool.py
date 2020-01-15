# -*- coding: utf-8 -*-
"""
Created on Fri Mar  9 13:22:07 2018
Updated on Sat Nov 23
@author: Kiranraj(kjogleka), Himanshu(hsardana), Komal(kpanzade), Avinash(avshukla)
"""
import warnings
warnings.filterwarnings(action='ignore',module='.*paramiko.*')
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
import tarfile
import shutil
from prettytable import PrettyTable, ALL
from collections import OrderedDict
from progressbar import ProgressBarThread
from multiprocessing import Process



########################       Logger        #################################
INFO = logging.INFO
DEBUG = logging.DEBUG
ERROR = logging.ERROR

def get_date_time():
    return (datetime.datetime.now().strftime("%d-%m-%Y_%I-%M-%S"))

def log_start(log_file, log_name, lvl):
    # Create a folder
    cdate = datetime.datetime.now()
    global dir_name
    dir_name = "HX_Report_" + str(cdate.strftime("%d_%m_%Y_%H_%M_%S"))
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
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%m-%d-%Y %I:%M:%S')
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

def check_psd(ips, hxusername, hxpassword, esxpassword, time_out):
    log_msg(INFO, "\r\nChecking the HX root password\r")
    ip = ips[0]
    esxip = ""
    try:
        # Initiate SSH Connection
        client.connect(hostname=ip, username=hxusername, password=hxpassword, timeout=time_out)
        msg = "\r\nSSH connection established to HX Node: " + ip + "\r"
        log_msg(INFO, msg)
        # Get ESX IP
        cmd = "/opt/springpath/storfs-mgmt-cli/getLocalNode.sh | grep 'esxiIP=' | cut -d= -f2"
        op = execmd(cmd)
        if "Not able to run the command" not in op:
            esxip = str(op[0]).strip()
        log_msg(INFO, "\r\nValid HX root password\r")
    except Exception as e:
        msg = "\r\nNot able to establish SSH connection to HX Node: " + ip + "\r"
        log_msg(INFO, msg)
        log_msg("", msg)
        log_msg(ERROR, str(e) + "\r")
        log_msg(INFO, "\r\nInvalid HX root password\r")
        log_msg("", "\r\nInvalid HX root password\r")
        sys.exit(0)

    if esxip != "":
        log_msg(INFO, "\r\nChecking the ESX root password\r")
        try:
            # Initiate SSH Connection
            client.connect(hostname=esxip, username=hxusername, password=esxpassword, timeout=time_out)
            msg = "\r\nSSH connection established to ESX Host: " + esxip + "\r"
            log_msg(INFO, msg)
            log_msg(INFO, "\r\nValid ESX root password\r")
        except Exception as e:
            msg = "\r\nNot able to establish SSH connection to ESX Host: " + esxip + "\r"
            log_msg(INFO, msg)
            log_msg("", msg)
            log_msg(ERROR, str(e) + "\r")
            log_msg(INFO, "\r\nInvalid ESX root password\r")
            log_msg("", "\r\nInvalid ESX root password\r")
            sys.exit(0)

def thread_geteth0ip(ip, hxusername, hxpassword, time_out):
    try:
        # Initiate SSH Connection
        client.connect(hostname=ip, username=hxusername, password=hxpassword, timeout=time_out)
        msg = "\r\nSSH connection established to HX Node: " + ip + "\r"
        log_msg(INFO, msg)
        #log_msg("", msg)
        #cmd = "hostname -i"
        cmd = "ifconfig eth0 | grep 'inet addr:' | cut -d: -f2| cut -d' ' -f1"
        hxip = execmd(cmd)
        hxips.extend(hxip)
        client.close()
    except Exception as e:
        msg = "\r\nNot able to establish SSH connection to HX Node: " + ip + "\r"
        log_msg(INFO, msg)
        log_msg("", msg)
        log_msg(ERROR, str(e) + "\r")

def thread_sshconnect(ip, hxusername, hxpassword, time_out):
    hostd[str(ip)] = dict.fromkeys(["hostname", "date", "ntp source", "package & versions", "check package & versions", "eth1", "esxip" "vmk0", "vmk1", "iptables count", "check iptables"], "")
    try:
        # Initiate SSH Connection
        client.connect(hostname=ip, username=hxusername, password=hxpassword, timeout=time_out)
        msg = "\r\nSSH connection established to HX Node: " + ip + "\r"
        log_msg(INFO, msg)
        log_msg("", msg)
        # Check hostname
        try:
            cmd = "hostname"
            hname = execmd(cmd)
            hostd[ip]["hostname"] = ("".join(hname)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e) + "\r")
        # Check NTP source
        try:
            cmd = "stcli services ntp show"
            hntp = execmd(cmd)
            hntp = [i for i in hntp if "-" not in i]
            hostd[ip]["ntp source"] = ("".join(hntp)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e) + "\r")
        # check package and versions
        try:
            cmd = "dpkg -l | grep -i springpath | cut -d' ' -f3,4-"
            op = execmd(cmd)
            pkgl = []
            for s in op:
                pkgl.append(s[:65])
            hostd[ip]["package & versions"] = pkgl
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

        except Exception as e:
            log_msg(ERROR, str(e) + "\r")
        # check Iptables count
        try:
            cmd = "iptables -L -n | wc -l"
            ipt = execmd(cmd)
            hostd[ip]["iptables count"] = ("".join(ipt)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e) + "\r")
    except Exception as e:
        msg = "\r\nNot able to establish SSH connection to HX Node: " + ip + "\r"
        log_msg(INFO, msg)
        log_msg("", msg)
        log_msg(ERROR, str(e) + "\r")
    finally:
        client.close()

def thread_timestamp(ip, hxusername, hxpassword, time_out):
    try:
        # Initiate SSH Connection
        client.connect(hostname=ip, username=hxusername, password=hxpassword, timeout=time_out)
        msg = "\r\nSSH connection established to HX Node: " + ip + "\r"
        log_msg(INFO, msg)
        #log_msg("", msg)
        # Check date
        try:
            cmd = 'date "+%D %T"'
            hdate = execmd(cmd)
            hostd[ip]["date"] = ("".join(hdate)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e) + "\r")
    except Exception as e:
        msg = "\r\nNot able to establish SSH connection to HX Node: " + ip + "\r"
        log_msg(INFO, msg)
        #log_msg("", msg)
        log_msg(ERROR, str(e) + "\r")
    finally:
        client.close()

def get_vmk1(ip, hxusername, esxpassword, time_out):
    esxip = hostd[ip].get("esxip", "")
    if esxip != "":
        try:
            # Initiate SSH Connection
            client.connect(hostname=esxip, username=hxusername, password=esxpassword, timeout=time_out)
            msg = "\r\nSSH connection established to ESX Host: " + esxip + "\r"
            log_msg(INFO, msg)
            log_msg("", msg)
            # Check vMotion Enabled
            try:
                cmd = "vim-cmd hostsvc/vmotion/netconfig_get | grep -i selectedVnic"
                op = execmd(cmd)
                vmst = "FAIL"
                vmknode = ""
                for line in op:
                    if "unset" in line:
                        vmst = "FAIL"
                    elif "VMotionConfig" in line:
                        vmst = "PASS"
                        v = re.search(r"vmk\d", line)
                        if v:
                            vmknode = v.group()
                esx_vmotion[esxip]["vmotion"] = vmst
                esx_vmotion[esxip]["vmknode"] = vmknode

            except Exception as e:
                log_msg(ERROR, str(e) + "\r")
            # Get vmk0 and vmk1 IP Address
            try:
                cmd = "esxcfg-vmknic -l"
                op = execmd(cmd)
                for line in op:
                    if "vmk0" in line and "IPv4" in line:
                        m1 = re.search(r"([\d]{1,3}(.[\d]{1,3}){3})", line)
                        if m1:
                            hostd[ip]["vmk0"] = str(m1.group(1))
                    elif "vmk1" in line and "IPv4" in line:
                        m2 = re.search(r"([\d]{1,3}(.[\d]{1,3}){3})", line)
                        if m2:
                            hostd[ip]["vmk1"] = str(m2.group(1))
                    # checking vmotion ip address
                    if vmknode != "":
                        if vmknode in line and "IPv4" in line:
                            m3 = re.search(r"([\d]{1,3}(.[\d]{1,3}){3})", line)
                            if m3:
                                esx_vmotion[esxip]["vmkip"] = str(m3.group(1))
                                if " 1500 " in line:
                                    esx_vmotion[esxip]["mtu"] = "1472"
                                elif " 9000 " in line:
                                    esx_vmotion[esxip]["mtu"] = "8972"
            except Exception as e:
                log_msg(ERROR, str(e) + "\r")
        except Exception as e:
            msg = "\r\nNot able to establish SSH connection to ESX Host: " + esxip + "\r"
            log_msg(INFO, msg)
            log_msg("", msg)
            log_msg(ERROR, str(e) + "\r")
        finally:
            client.close()

def pingstatus(op):
    pgst = "PASS"
    for line in op:
        if "Not able to run the command" in line or "Network is unreachable" in line:
            pgst = "FAIL"
        elif "0 packets received" in line or "100% packet loss" in line or " 0 received" in line:
            pgst = "FAIL"
        elif ", 0% packet loss" in line:
            pgst = "PASS"
    return pgst

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
    # 1) Mode
    # echo srvr | nc localhost 2181
    cmd = "echo srvr | nc localhost 2181"
    zkl = execmd(cmd)
    mode = ""
    for line in zkl:
        if "Mode:" in line:
            mode = line.split(": ")[1]

    # 2) Services
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
            
    # 3) Check exhibitor.properties file exists
    cmd = "ls /etc/exhibitor/exhibitor.properties"
    op = execmd(cmd)
    prop_file = ""
    for line in op:
        if "exhibitor.properties" in line:
            prop_file = "Exists"
        else:
            prop_file = "Not Exists"

    # Epoch Issue
    # 4) Accepted Epoch value
    # 5) Current Epoch value
    cmd = 'grep -m1 "" /var/zookeeper/version-2/acceptedEpoch'
    op = execmd(cmd)
    accepoch = "".join(op)
    cmd = 'grep -m1 "" /var/zookeeper/version-2/currentEpoch'
    op = execmd(cmd)
    curepoch = "".join(op)

    # 6) Disk usage
    # Each should be less than 80%
    cmd = "df -h | grep -i '/var/stv\|/var/zookeeper\|/sda1'"
    diskop = execmd(cmd)
    zdiskchk = "PASS"
    zdisk = ""
    for line in diskop:
        if "Not able to run the command" in line:
            zdiskchk = "NA"
            break
        elif "/sda1" in line:
            m1 = re.search(r"(\d+)%", line)
            if m1:
                if int(m1.group(1)) > 80:
                    zdiskchk = "FAIL"
                    zdisk = "/sda1"
                    break
        elif "/var/stv" in line:
            m2 = re.search(r"(\d+)%", line)
            if m2:
                if int(m2.group(1)) > 80:
                    zdiskchk = "FAIL"
                    zdisk = "/var/stv"
                    break
        elif "/var/zookeeper" in line:
            m3 = re.search(r"(\d+)%", line)
            if m3:
                if int(m3.group(1)) > 80:
                    zdiskchk = "FAIL"
                    zdisk = "/var/zookeeper"
                    break

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

    # Disk Usage
    testdetail[ip]["ZooKeeper and Exhibitor check"]["ZooKeeper Disk Usage"] = {"Status": zdiskchk, "Result": zdisk}

    # Update Test summary
    zoo_chk = "FAIL"
    exh_chk = "FAIL"
    if mode == "follower" or mode == "leader" or mode == "standalone":
        zoo_chk = "PASS"
    if "running" in exh_service.lower():
        exh_chk = "PASS"
    testsum[ip].update({"Zookeeper check": zoo_chk})
    testsum[ip].update({"Exhibitor check": exh_chk})
    testsum[ip].update({"ZooKeeper Disk Usage": zdiskchk})
    
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
    vflag = False
    for line in hxvs:
        if "Cluster version" in line:
            l = line.split(": ")
            if len(l) == 2:
                version = l[1]
                hostd[ip]["version"] = version.strip()
                if l[1].startswith("1.8"):
                    vflag = True
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
    cmd = "ntpq -p -4 | grep '^*'"
    ntpsl = execmd(cmd)
    ntp_sync_check = "FAIL"
    ntp_sync_line = ""
    flag1 = 0
    for line in ntpsl:
        if "Not able to run the command" in line:
            ntp_sync_check = "FAIL"
        elif line.startswith("*"):
            l = line.split()
            ntp_sync_line = l[0]
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
        #cmd = "ping {} -c 3 -i 0.01".format(dnsip)
        cmd = "dig @{}".format(dnsip)
        dns_check = "FAIL"
        digop = execmd(cmd)
        for line in digop:
            if "HEADER" in line and "status: NOERROR" in line:
                dns_check = "PASS"
                break
            elif "OPT PSEUDOSECTION:" in line:
                break
        digop = [(str(l).rstrip()).replace("\t", " "*5) for l in digop]
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
                if len(l) == 3:
                    dnip = l[2]
                    dnip = dnip.replace("//", "")
                    vcenterip = dnip.strip()
                    msg = "\r\nvCenter FQDN: " + str(vcenterip) + "\r"
                    log_msg(INFO, msg)
            except Exception:
                pass

    if vcenterip:
        cmd = "ping {} -c 3 -i 0.01".format(vcenterip)
        op = execmd(cmd)
        vcenter_check = pingstatus(op)

    # Update Test summary
    testsum[ip].update({"vCenter reachability check": vcenter_check})
    testsum[ip].update({"Timestamp check": str(hostd[ip]["date check"])})
    if ntp_deamon_check == "PASS" and hostd[ip]["ntp source check"] == "PASS" and ntp_sync_check == "PASS":
        testsum[ip].update({"NTP sync check": "PASS"})
    else:
        testsum[ip].update({"NTP sync check": "FAIL"})
    testsum[ip].update({"Check package & versions": str(hostd[ip]["check package & versions"])})
    testsum[ip].update({"Check Iptables count": str(hostd[ip]["check iptables"])})
    # 5) Check cluster usage
    cmd = "stcli cluster storage-summary | grep -i nodeFailuresTolerable"
    op = execmd(cmd)
    op = "".join(op)
    op = op.strip()
    if ":" in op:
        NFT = op.split(":")[1]
    else:
        NFT = "NA"
    cmd = "stcli cluster storage-summary | grep -i cachingDeviceFailuresTolerable"
    op = execmd(cmd)
    op = "".join(op)
    op = op.strip()
    if ":" in op:
        HFT = op.split(":")[1]
    else:
        HFT = "NA"
    cmd = "stcli cluster storage-summary | grep -i persistentDeviceFailuresTolerable"
    op = execmd(cmd)
    op = "".join(op)
    op = op.strip()
    if ":" in op:
        SFT = op.split(":")[1]
    else:
        SFT = "NA"
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
    # Fail, when not able to run
    cmd = "stcli cluster upgrade-status"
    upst = "PASS"
    op = execmd(cmd)
    for line in op:
        if "Not able to run the command" in line:
            upst = "FAIL"
            break
    # Update Test summary
    if vflag == False:
        testsum[ip].update({"Cluster upgrade status": upst})
    # 8) Check any extra number of pnodes
    cmd = "stcli cluster info | grep -i  pnode -n2 | grep -i name | wc -l"
    op = execmd(cmd)
    op = "".join(op)
    pnodes = int(op)
    check_cache_vnodes = ""
    if cachl:
        if pnodes == len(cachl):
            check_cache_vnodes = "PASS"
        else:
            check_cache_vnodes = "FAIL"
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
    # 10) check packages and versions(Moved to Thread)
    # check memory
    #cmd = "free -m"
    cmd = "free -m | grep Mem:"
    op = execmd(cmd)
    check_memory = "NA"
    if op:
        for line in op:
            l = line.split()
            frmem = int(l[-1])
            if int(frmem) >= 2048:
                check_memory = "PASS"
            else:
                check_memory = "FAIL"
    testsum[ip].update({"Memory usage check": check_memory})
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
        testsum[ip].update({"Incidence of OOM in the log file": "PASS"})
    else:
        check_oom = op
        testsum[ip].update({"Incidence of OOM in the log file": "FAIL"})
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
    # Check permissions for /tmp
    cmd = "ls -ld /tmp"
    op = execmd(cmd)
    tmprcheck = ""
    for line in op:
        if line.startswith("drwxr-xrwx"):
            tmprcheck = "PASS"
        else:
            tmprcheck = "FAIL"
    testsum[ip].update({"Check permissions for /tmp": tmprcheck})
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
    testdetail[ip]["Pre-Upgrade check"]["DNS check"] = {"Status": str("\n".join(digop)), "Result": dns_check}
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
    testdetail[ip]["Pre-Upgrade check"]["Cache vNodes"] = {"Status": str("\n".join(cachl)), "Result": check_cache_vnodes}
    # Cluster Upgrade
    if vflag == False:
        testdetail[ip]["Pre-Upgrade check"]["Cluster Upgrade Status"] = upst
    # No extra pnodes
    testdetail[ip]["Pre-Upgrade check"]["No extra pnodes"] = nodecheck
    # Disk usage(/var/stv)
    testdetail[ip]["Pre-Upgrade check"]["Disk usage(/var/stv)"] = {"Status": str(dskusg) + "%", "Result": dskst}
    # Check package & versions
    testdetail[ip]["Pre-Upgrade check"]["Check package & versions"] = {"Status": str("\n".join(hostd[ip]["package & versions"])), "Result": str(hostd[ip]["check package & versions"])}
    # Check Iptables count
    testdetail[ip]["Pre-Upgrade check"]["Check Iptables count"] = {"Status": str(hostd[ip]["iptables count"]), "Result": str(hostd[ip]["check iptables"])}
    # Check memory
    testdetail[ip]["Pre-Upgrade check"]["Check Memory usage"] = str(check_memory)
    # Check CPU
    testdetail[ip]["Pre-Upgrade check"]["Check CPU"] = str("\n".join(check_cpu))
    # Check Out of memory
    testdetail[ip]["Pre-Upgrade check"]["Incidence of OOM in the log file"] = str("\n".join(check_oom))
    # Supported vSphere versions
    testdetail[ip]["Pre-Upgrade check"]["Supported vSphere versions"] = str("\n".join(svsp))
    # Check permissions for /tmp
    testdetail[ip]["Pre-Upgrade check"]["Check permissions for /tmp"] = tmprcheck

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
                    if "hxuser" in line or "springpath" in line:
                        hxac = "PASS"
                opd.update({"HX User Account Created": hxac})
            except Exception:
                pass
            # Check vMotion Enabled
            vmst = esx_vmotion[esxip]["vmotion"]
            opd.update({"vMotion Enabled": vmst})
            # Check vMotion reachability check
            allvmkpingchk = []
            vmknode = esx_vmotion[esxip].get("vmknode", "")
            if vmst == "PASS" and vmknode != "":
                for vip in esx_vmotion.keys():
                    mtu = esx_vmotion[str(vip)]["mtu"]
                    vmkip = esx_vmotion[str(vip)]["vmkip"]
                    if vip == esxip:
                        continue
                    elif vmkip != "":
                        try:
                            cmd = "vmkping -I {} -c 3 -d -s {} {}".format(vmknode, mtu, vmkip)  # Removed vmotion netstack due to CSCvo58388
                            op = execmd(cmd)
                            pst = pingstatus(op)
                            opd.update({cmd: pst})
                            allvmkpingchk.append(pst)
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
            vibl = []
            try:
                cmd = "esxcli software vib list| grep -i spring"
                op = execmd(cmd)
                for line in op:
                    vibl.append(line.replace(" "*26, "    "))
                opd.update({"ESX Vib List": vibl})
            except Exception:
                pass
            # check SCVM and STFSNasPlugin version
            # scvmclient version should match the hx cluster version.
            chknasplg = ""
            chkscvm = ""
            nasplugin = {"1.8": "1.0.1-21", "2.1": "1.0.1-21", "2.5": "1.0.1-21", "2.6": "1.0.1-21",
                         "3.0": "1.0.1-22", "3.5": "1.0.1-22", "4.0": "1.0.1-22"}
            hxv = (hostd[ip]["version"])[:3]
            if float(hxv) <= 3.5 and vibl:
                for vl in vibl:
                    if "scvmclient" in vl:
                        l = vl.split()
                        v = hostd[ip]["version"]
                        v = v.replace("(", ".")
                        v = v.replace(")", "")
                        if v in l[1]:
                            chkscvm = "PASS"
                        else:
                            chkscvm = "FAIL"
                    elif "STFSNasPlugin" in vl:
                        l = vl.split()
                        m = re.search(r"^3\.0\(1[a-i]\)", hostd[ip]["version"])
                        if m:
                            if l[1] == "1.0.1-21":
                                chknasplg = "PASS"
                            else:
                                chknasplg = "FAIL"
                        elif hxv in nasplugin.keys():
                            if nasplugin[hxv] == l[1]:
                                chknasplg = "PASS"
                            else:
                                chknasplg = "FAIL"
                opd.update({"Check SCVM plugin version": chkscvm})
                opd.update({"Check STFSNas plugin version": chknasplg})
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
                        cmd = "vmkping -I {} -c 3 -d -s 8972 -i 0.01 {}".format("vmk1", k)
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
                cmd = "esxcli hardware platform get | grep -i serial | grep -vi enclosure"  # In response to issue no.7
                op = execmd(cmd)
                srno = ""
                vmfld = ""
                for line in op:
                    if line.startswith("Serial Number"):
                        l = line.split(": ")
                        try:
                            srno = l[1]
                            srno = srno.strip()
                        except Exception:
                            pass
                        break
                if srno != "":
                    cmd = "ls /vmfs/volumes/SpringpathDS-" + str(srno.strip())
                    op = execmd(cmd)
                    op = [x for x in op if x != ""]
                    vmfld = "PASS"
                    #print(len(op))
                    fcnt = 0
                    if op:
                        for line in op:
                            l = line.split()
                            for d in l:
                                if d.startswith("stCtlVM"):
                                    fcnt += 1
                    if fcnt > 1:
                        vmfld = "FAIL" + "\nBug: HX Down"
                opd.update({"No extra controller vm folders": vmfld})
            except Exception:
                pass
            # Check the dump in springpathDS for HX < 2.5
            chkdump = ""
            # check for all HX versions
            # If the dumpfile present, then it is Fail
            try:
                cmd = "ls /vmfs/volumes/Spri*/vmkdump"
                op = execmd(cmd)
                for line in op:
                    if "Not able to run the command" in line:
                        chkdump = "NA"
                    elif ".dumpfile" in line:
                        chkdump = "FAIL"
                    elif "No such file or directory" in line:
                        chkdump = "PASS"
                    else:
                        chkdump = "PASS"
                opd.update({"Check the dump in springpathDS": chkdump})
            except Exception:
                pass
            # VMware Tools location check:
            try:
                cmd = "esxcli system settings advanced list -o /UserVars/ProductLockerLocation | grep -i 'string value'"
                op = execmd(cmd)
                svalue = ""
                dsvalue = ""
                vmtoolcheck = ""
                for line in op:
                    if line.startswith("String Value"):
                        svalue = line.split(": ")[1]
                    elif line.startswith("Default String Value"):
                        dsvalue = line.split(": ")[1]
                if svalue != "" and dsvalue != "":
                    if svalue == dsvalue:
                        vmtoolcheck = "PASS"
                    else:
                        vmtoolcheck = "FAIL"
                opd.update({"VMware Tools location check": vmtoolcheck})
            except Exception:
                pass
            # Update Test Detail
            nwtestdetail.update({esxip: opd})
            # Close connection
            client.close()

            # Test summary
            # HX User Account check
            nwtestsum[esxip]["HX User Account check"] = hxac
            # vMotion enabled check
            nwtestsum[esxip]["vMotion enabled check"] = esx_vmotion[esxip]["vmotion"]
            # vMotion reachability check
            if esx_vmotion[esxip]["vmotion"] == "PASS":
                if allvmkpingchk:
                    if "FAIL" in allvmkpingchk:
                        nwtestsum[esxip]["vMotion reachability check"] = "FAIL"
                    else:
                        nwtestsum[esxip]["vMotion reachability check"] = "PASS"
            # Check for HX down during upgrade
            #nwtestsum[esxip]["Check for HX down during upgrade"] = check_HX_down_status[:4]
            if check_HX_down_status == "FAIL":
                nwtestsum[esxip]["Check for ESXI Failback timer"] = {"Status": check_HX_down_status, "Result": "If Failed, Change the failback timer to 30secs" + "\nesxcli system settings advanced set -o /Net/TeamPolicyUpDelay --int-value 30000"}
            else:
                nwtestsum[esxip]["Check for ESXI Failback timer"] = {"Status": check_HX_down_status, "Result": ""}
                # Check ping to vmk0, eth0, eth1
            if allpingchk:
                if "FAIL" in allpingchk:
                    nwtestsum[esxip]["Check ping to vmk0, eth0, eth1"] = "FAIL"
                else:
                    nwtestsum[esxip]["Check ping to vmk0, eth0, eth1"] = "PASS"
            # Check the dump in springpathDS for HX < 2.5
            if chkdump != "":
                nwtestsum[esxip]["Check the dump in springpathDS"] = chkdump
            if chkscvm != "":
                nwtestsum[esxip]["Check SCVM plugin version"] = chkscvm
            if chknasplg != "":
                nwtestsum[esxip]["Check STFSNas plugin version"] = chknasplg
            # No extra controller vm folders check
            nwtestsum[esxip]["No extra controller vm folders check"] = vmfld[:4]
            # VMware Tools location check
            nwtestsum[esxip]["VMware Tools location check"] = vmtoolcheck

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
        fh.write("\t\t\t     HX Health Check " + str(toolversion))
        fh.write("\r\n")
        fh.write("\t\t\tHX Controller: " + ip)
        fh.write("\r\n")
        fh.write("\t\t\tHX Hostname: " + hostd[ip].get("hostname", ""))
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


def create_main_report(clustername):
    # create main report file
    filename = "HX_Tool_Main_Report_" + get_date_time() + "_" + str(clustername.strip()) + ".txt"
    with open(filename, "w") as fh:
        fh.write("\t\t\tHX Health Check " + str(toolversion))
        fh.write("\r\n")
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
        fh.write("\r\nRelease Notes:" + "\r\n")
        fh.write("https://www.cisco.com/c/en/us/support/hyperconverged-systems/hyperflex-hx-data-platform-software/products-release-notes-list.html" + "\r\n")
        fh.write("\r\nUpgrade Guides:" + "\r\n")
        fh.write("https://www.cisco.com/c/en/us/support/hyperconverged-systems/hyperflex-hx-data-platform-software/products-installation-guides-list.html" + "\r\n")
        fh.write("\r\n")
        fh.write("\r\nNote:" + "\r\n")
        fh.write("1) Please check the status of Compute nodes manually, script only verifies the config on the converged nodes." + "\r\n")
        fh.write("2) Hypercheck doesnot perform FAILOVER TEST, so please ensure that the upstream is configured for network connectivity for JUMBO or NORMAL MTU size as needed." + "\r\n")
        fh.write("\r\n")
    print("\r\nMain Report File: " + filename)
    create_tar_file()
    print("\r\nRelease Notes:")
    print("\rhttps://www.cisco.com/c/en/us/support/hyperconverged-systems/hyperflex-hx-data-platform-software/products-release-notes-list.html")
    print("\r\nUpgrade Guides:")
    print("\rhttps://www.cisco.com/c/en/us/support/hyperconverged-systems/hyperflex-hx-data-platform-software/products-installation-guides-list.html")
    print("\r\nNote:")
    print("\r1) Please check the status of Compute nodes manually, script only verifies the config on the converged nodes.")
    print("\r2) Hypercheck doesnot perform FAILOVER TEST, so please ensure that the upstream is configured for network connectivity for JUMBO or NORMAL MTU size as needed.")
    print("\r\n")

def create_tar_file():
    file = dir_name + ".tar"
    try:
        os.chdir("..")
        tar = tarfile.open(file, "w")
        tar.add(dir_name)
        tar.close()
        print("Report tar file: " + str(file))
        # Copy file to /var/log/springpath
        path = r"/var/log/springpath/"
        shutil.copy(file, path)
        print("Report file copied to path: /var/log/springpath")
    except Exception as e:
        print("Not able to create the Report tar file")
        print(e)


###############################################################################
# Main Starts here
###############################################################################
if __name__ == "__main__":
    # HX Script version
    global toolversion
    toolversion = 3.6
    # Arguments passed
    global arg
    arg = ""
    if len(sys.argv) > 1:
        try:
            arg = (sys.argv[1]).lower()
        except Exception:
            pass
    if arg == "-h" or arg == "--help" or arg == "help":
        print("\n\t\t HX Health Check " + str(toolversion))
        print("\nSupported HX Versions: 1.8, 2.6, 3.0, 3.5, 4.0")
        print("\nPre-requisite: Script needs HX and ESXi root password information to check all conditions.")
        print("\nHX Health Check script will do below checks on each cluster nodes:")
        print("\t 1) Cluster services check")
        print("\t 2) ZooKeeper & Exhibitor check")
        print("\t 3) HDD health check")
        print("\t 4) Pre-Upgrade Check")
        print("\t 5) Network check ")
        print("\nFor Test Summary report run as below:")
        print("\t python HXTool.py")
        print("\nFor Test detail report run as below:")
        print("\t python HXTool.py detail\n")
        sys.exit(0)

    # Log file declaration
    log_file = "HX_Tool_" + get_date_time() + ".log"
    log_name = "HX_TOOL"
    log_start(log_file, log_name, INFO)

    # RSA_KEY_FILE = "/etc/ssh/ssh_host_rsa_key"

    print("\n\t\t HX Health Check " + str(toolversion))
    log_msg(INFO, "HX Health Check " + str(toolversion) + "\r")
    # HX Controller parameter
    print("\nPlease enter below info of HX-Cluster:")
    hxusername = "root"
    log_msg(INFO, "Username: " + hxusername + "\r")
    hxpassword = getpass.getpass("Enter the HX-Cluster Root Password: ")
    esxpassword = getpass.getpass("Enter the ESX Root Password: ")
    port = 22
    hostip = ""
    hostpath = ""
    log_msg(INFO, "Port: " + str(port) + "\r")
    time_out = 30  # Number of seconds for timeout
    log_msg(INFO, "Timeout: " + str(time_out) + "\r")
    # Get Host IP Address of eth1
    # cmd = "hostname -i"
    cmd = "ifconfig eth1 | grep 'inet addr:' | cut -d: -f2| cut -d' ' -f1"
    op = runcmd(cmd)
    hostip = op.strip()
    log_msg(INFO, "Host IP Address: " + str(hostip) + "\r")
    # Get Host Path
    cmd = "pwd"
    op = runcmd(cmd)
    hostpath = op.strip()
    log_msg(INFO, "Host Path: " + str(hostpath) + "\r")
    log_msg(INFO, "Argument: " + str(arg) + "\r")
    if arg == "detail":
        print("Option: " + str(arg))

    # Get Cluster name
    clustername = ""
    cmd = "stcli cluster info | grep -A 6 'vCluster:' | grep 'name:' | cut -d:  -f2"
    op = runcmd(cmd)
    if "Not able to run the command" in op:
        pass
    else:
        clustername = op.strip()
    log_msg(INFO, "Cluster Name: " + str(clustername) + "\r")

    # Get Controller Mgmnt IP Addresses
    # Old cmd used to get controller IP Addresses
    # cmd1 = "stcli cluster info | grep -i  stctl_mgmt -n1 | grep -i addr"
    # Get eth1 ips
    cmd = "sysmtool --ns cluster --cmd info | grep -i uuid"
    op = runcmd(cmd)
    if op:
        ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", op)
    if not ips:
        print("HX Nodes IP Addresses are not found")
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

    # Check HX and ESX root Password
    check_psd(ips, hxusername, hxpassword, esxpassword, time_out)

    # Get all hostnames and HX IP address using threads
    # <hostname -i> cmd is not working
    try:
        ipthreads = []
        for ip in ips:
            th = threading.Thread(target=thread_geteth0ip, args=(ip, hxusername, hxpassword, time_out,))
            th.start()
            time.sleep(12)
            ipthreads.append(th)

        for t in ipthreads:
            t.join()

        hxips.sort(key=lambda ip: map(int, reversed(ip.split('.'))))
    except Exception:
        hxips = eth1_list

    log_msg(INFO, "HX IP Adresses: " + ", ".join(hxips) + "\r")

    #############################################################
    # Create instance of SSHClient object
    client = paramiko.SSHClient()

    # Automatically add untrusted hosts (Handle SSH Exception for unknown host)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Get hostname, eth1, esxip using threads
    threads = []
    for ip in hxips:
        th = threading.Thread(target=thread_sshconnect, args=(ip, hxusername, hxpassword, time_out,))
        th.start()
        time.sleep(30)
        threads.append(th)

    for t in threads:
        t.join()

    # Get all timestamp using threads
    tsthreads = []
    tsstart = datetime.datetime.now().replace(microsecond=0)
    for ip in hxips:
        th = threading.Thread(target=thread_timestamp, args=(ip, hxusername, hxpassword, time_out,))
        th.start()
        time.sleep(5)
        tsthreads.append(th)

    for t in tsthreads:
        t.join()
    tsend = datetime.datetime.now().replace(microsecond=0)
    timedelay = (tsend - tsstart).seconds
    log_msg(INFO, "Time delay for Timestamp check: " + str(timedelay) + "\r")

    global ht
    ht = PrettyTable(hrules=ALL)
    ht.field_names = ["Nodes", "IP Address", "HostName"]
    ht.align = "l"
    for i, ip in enumerate(hxips):
        ht.add_row([i + 1, ip, hostd[ip].get("hostname", "")])
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
                            if t > timedelay:
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

    # Check package & versions on each controller
    packagecheck = ""
    # First will count no of packages on each controller
    for ip in hostd.keys():
        ipkgl = hostd[ip]["package & versions"]
        if ipkgl:
            cnt = len(ipkgl)
            for jp in hostd.keys():
                if ip == jp:
                    continue
                elif cnt == len(hostd[jp]["package & versions"]):
                    packagecheck = "PASS"
                else:
                    packagecheck = "FAIL"
                    break
            break
        else:
            packagecheck = "FAIL"
            break
    # Now will check package and version on each controller
    if packagecheck == "PASS":
        for ip in hostd.keys():
            ipkgl = hostd[ip]["package & versions"]
            for pk in ipkgl:
                pkg = ""
                ver = ""
                l = pk.split()
                try:
                    pkg = l[0]
                    ver = l[1]
                except Exception:
                    pass
                for jp in hostd.keys():
                    if ip == jp:
                        continue
                    elif packagecheck == "FAIL":
                        break
                    else:
                        jpkgl = hostd[jp]["package & versions"]
                        for line in jpkgl:
                            if pkg in line:
                                if ver in line:
                                    packagecheck = "PASS"
                                else:
                                    packagecheck = "FAIL"
                                    break
                if packagecheck == "FAIL":
                    break
            if packagecheck == "FAIL":
                break
    for ip in hostd.keys():
        hostd[ip]["check package & versions"] = packagecheck
    # check Iptables count
    # check for at least 44 and same across all nodes
    iptst = ""
    for ip in hostd.keys():
        try:
            ipcnt = int(hostd[ip]["iptables count"])
        except Exception:
            continue
        if ipcnt < 44:
            iptst = "FAIL"
            break
        elif iptst == "FAIL":
            break
        else:
            for jp in hostd.keys():
                try:
                    jpcnt = int(hostd[jp]["iptables count"])
                except Exception:
                    continue
                if jpcnt < 44:
                    iptst = "FAIL"
                    break
                elif ip == jp:
                    continue
                elif ipcnt == jpcnt:
                    iptst = "PASS"
                else:
                    iptst = "FAIL"
                    break
    for ip in hostd.keys():
        hostd[ip]["check iptables"] = iptst

    # Get ESX IPs, vmk1 ips
    global esx_hostsl
    esx_hostsl = []
    for ip in hostd.keys():
        esxip = hostd[ip].get("esxip", "")
        if esxip != "":
            esx_hostsl.append(esxip)
    if esx_hostsl:
        try:
            esx_hostsl.sort(key=lambda ip: map(int, reversed(ip.split('.'))))
        except Exception:
            pass
    global esx_vmotion
    esx_vmotion = {}
    for ip in esx_hostsl:
        esx_vmotion[str(ip)] = dict.fromkeys(["vmotion", "vmkip", "mtu"], "")
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

    # print(esx_vmotion)
    for ip in hostd.keys():
        vmk1 = hostd[ip]["vmk1"]
        vmk1_list.append(vmk1)

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
            msg = "\r\nSSH connection established to HX Node: " + ip + "\r"
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

        except KeyboardInterrupt:
            sys_exit(0)

        except Exception as e:
            msg = "\r\nNot able to establish SSH connection to HX Node: " + ip + "\r"
            log_msg(INFO, msg)
            # log_msg("", msg)
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
    create_main_report(clustername)

    # End
    sys_exit(0)
