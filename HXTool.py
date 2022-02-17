# -*- coding: utf-8 -*-
"""
Created on 9-Mar-2018
Updated on 29-Apr-2020
@author: Kiranraj(kjogleka), Himanshu(hsardana), Komal(kpanzade), Avinash(avshukla)
"""
import warnings
warnings.filterwarnings('ignore')
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
import json
import tarfile
from prettytable import PrettyTable, ALL
from collections import OrderedDict
from progressbar import ProgressBarThread
from multiprocessing import Process

# Global Variables
toolversion = 4.2
builddate = "2021-04-29"
sedNote = False
lsusbCheck = False

########################       Logger        #################################
INFO = logging.INFO
DEBUG = logging.DEBUG
ERROR = logging.ERROR


def get_date_time():
    return (datetime.datetime.now().strftime("%Y-%m-%d_%I-%M-%S"))


def log_start(log_file, log_name, lvl):
    # Create a folder
    cdate = datetime.datetime.now()
    global dir_name
    dir_name = "HX_Report_" + str(cdate.strftime("%Y_%m_%d_%H_%M_%S"))
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
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%Y-%m-%d %I:%M:%S')
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
    # Exit the logger and stop the script, used for traceback error handling
    log_msg(INFO, "Closing logger and exiting the application\r")
    msg = "HX Checkup Tool Stopped at Date/Time :" + get_date_time().replace("_", "/") + "\r"
    log_msg(INFO, msg)
    end_time = datetime.datetime.now()
    time_diff = end_time - start_time
    msg = "Test duration: " + str(time_diff.seconds) + " seconds"
    log_msg(INFO, msg)
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
    # Shutdown the logger handler
    try:
        log_stop()
    except Exception:
        pass
    sys.exit(val)


####################           SSH connection            #####################


def runcmd(cmd, display=True):
    # Execute local shell command
    log_entry(cmd)
    log_msg(INFO, "$" * 61 + "\r")
    log_msg(INFO, "\r\nExecuting Shell command: " + cmd + "\r")
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    cmdoutput, err = p.communicate()
    p_status = p.wait()
    output = cmdoutput.split("\n")
    log_msg(INFO, "*" * 24 + " CMD OUTPUT " + "*" * 24 + "\r")
    if display:
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
        eth0_list.extend(hxip)
        client.close()
    except Exception as e:
        msg = "\r\nNot able to establish SSH connection to HX Node: " + ip + "\r"
        log_msg(INFO, msg)
        log_msg("", msg)
        log_msg(ERROR, str(e) + "\r")


def thread_sshconnect(ip, hxusername, hxpassword, time_out):
    hostd[str(ip)] = dict.fromkeys(["hostname", "date", "ntp source", "package & versions", "check package & versions", "eth1", "esxip" "vmk0", "vmk1", "iptables count", "check iptables", "keystore"], "")
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
            hntp = [i for i in hntp if "----" not in i]
            hostd[ip]["ntp source"] = (",".join(hntp)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e) + "\r")
        # check package and versions
        try:
            #cmd = "dpkg -l | grep -i springpath | cut -d' ' -f3,4-"
            cmd = "dpkg -l | grep -i springpath | grep -v storfs-support* | cut -d' ' -f3,4-"
            op = execmd(cmd)
            pkgl = []
            for s in op:
                pkgl.append(s[:65])
            hostd[ip]["package & versions"] = pkgl
        except Exception as e:
            log_msg(ERROR, str(e) + "\r")
        # Get eth1 IP Address
        try:
            cmd = "ifconfig eth0 | grep 'inet addr:' | cut -d: -f2| cut -d' ' -f1"
            eth1ip = execmd(cmd)
            hostd[ip]["eth0"] = ("".join(eth1ip)).encode("ascii", "ignore")
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
        # Get keystore file
        try:
            cmd = "md5sum /etc/springpath/secure/springpath_keystore.jceks"
            op = execmd(cmd)
            if op:
                keystoreFile = op[0]
                hostd[ip]["keystore"] = keystoreFile.strip()
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
        vmknode = ""
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
                    if "vmk1" in line and "IPv4" in line:
                        m = re.search(r"([\d]{1,3}(.[\d]{1,3}){3})", line)
                        if m:
                            vmk1 = str(m.group(1))
                            hostd[ip]["vmk1"] = vmk1
                            vmk1_list.append(vmk1)
                            vmk1_mtu[vmk1] = {}
                            if " 1500 " in line:
                                vmk1_mtu[vmk1]["mtu"] = "1472"
                            elif " 9000 " in line:
                                vmk1_mtu[vmk1]["mtu"] = "8972"
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
        elif line.startswith("SCVM Client") and "Not" in line:
            cluster_service_chk = "FAIL"
            break
        elif "System Management Service" in line and "Not" in line:
            cluster_service_chk = "FAIL"
            break
        elif "Cluster IP Monitor" in line and "Not" in line:
            cluster_service_chk = "FAIL"
            break
    testsum[ip]["Cluster services check"] = {"Status": cluster_service_chk, "Result": "Checks storfs, stMgr, sstNodeMgr and CIP-Monitor services are running on each node."}
    testsum[ip]["Enospc state check"] = {"Status": enospc_state_check, "Result": "Checks if the cluster storage utilization is above threshold."}


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
        if "Not able to run the command" in line:
            prop_file = "Not Exists"
            break
        elif "exhibitor.properties" in line and not("cannot access" in line):
            prop_file = "Exists"
        else:
            prop_file = "Not Exists"

    # Epoch Issue
    # 4) Accepted Epoch value
    # 5) Current Epoch value
    cmd = "grep -m1 '' /var/zookeeper/version-2/acceptedEpoch"
    op = execmd(cmd)
    acflag = 0
    for line in op:
        if "Not able to run the command" in line or "No such file or directory" in line:
            acflag = 1
    if acflag:
        accepoch = ""
    else:
        accepoch = "".join(op)
    cmd = "grep -m1 '' /var/zookeeper/version-2/currentEpoch"
    op = execmd(cmd)
    cuflag = 0
    for line in op:
        if "Not able to run the command" in line or "No such file or directory" in line:
            cuflag = 1
    if cuflag:
        curepoch = ""
    else:
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
    testdetail[ip]["ZooKeeper and Exhibitor check"]["System Disks Usage"] = {"Status": zdiskchk, "Result": zdisk}

    # Update Test summary
    zoo_chk = "FAIL"
    exh_chk = "FAIL"
    if mode == "follower" or mode == "leader" or mode == "standalone":
        zoo_chk = "PASS"
    if "running" in exh_service.lower():
        exh_chk = "PASS"
    testsum[ip]["Zookeeper check"] = {"Status": zoo_chk, "Result": "Checks if Zookeeper service is running."}
    testsum[ip]["Exhibitor check"] = {"Status": exh_chk, "Result": "Checks if Exhibitor in running."}
    testsum[ip]["System Disks Usage"] = {"Status": zdiskchk, "Result": "Checks if /sda1, var/stv and /var/zookeeper is less than 80%."}

    
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
    bdisklist = []
    for line in op:
        bdsk = line.strip()
    if bdsk != "":
        cmd = "sysmtool --ns disk --cmd list"
        opl = execmd(cmd)
        flg1 = flg2 = 0
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
    testdetail[ip]["HDD Health check"] = OrderedDict()
    # Claimed
    testdetail[ip]["HDD Health check"]["Claimed"] = cdsk

    #Blacklisted
    testdetail[ip]["HDD Health check"]["Blacklisted"] = {"Status": bdsk, "Result": "\n".join(bdisklist)}

    # Ignored
    testdetail[ip]["HDD Health check"]["Ignored"] = idsk

    # Update Test summary
    hd_chk = "PASS"
    if int(bdsk) > 0:
        hd_chk = "FAIL"
    testsum[ip]["HDD Health check"] = {"Status": hd_chk, "Result": "Checks if any drive is in blacklisted state."}


def pre_upgrade_check(ip):
    # Pre-Upgrade Check
    # 1) Check HX Cluster version
    cmd = "stcli cluster version"
    hxvs = execmd(cmd)
    vflag = False
    global sedflag
    for line in hxvs:
        if "Cluster version" in line:
            l = line.split(": ")
            if len(l) == 2:
                version = l[1]
                #Cluster version: Version(4.0.2a-35118)
                if "Version" in version:
                    m = re.search(r"\((.+)\)", version)
                    if m:
                        hostd[ip]["version"] = m.group(1)
                else:
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

    # 4) DNS check
    cmd = "stcli services dns show"
    op = execmd(cmd)
    dnsip = ""
    dns_check = "FAIL"
    digop = []
    for line in op:
        match = re.search(r"(?:\d{1,3}.){3}\d{1,3}", line)
        if match:
           dnsip = match.group()
           msg = "\r\nDNS IP Address: " + str(dnsip) + "\r"
           log_msg(INFO, msg)
    if dnsip:
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
    if dns_check == "PASS":
        testsum[ip]["DNS check"] = {"Status": "PASS", "Result": "Checks if configured DNS is reachable."}
    else:
        testsum[ip]["DNS check"] = {"Status": "FAIL", "Result": "Please verify DNS resolution and connectivity."}

    # 5) vCenter Reachability check
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
                l = line.split(": ")
                if len(l) == 2:
                    dnip = l[1]
                    dnip = dnip.replace("https://", "")
                    vcenterip = dnip.strip()
                    msg = "\r\nvCenter IP Address: " + str(vcenterip) + "\r"
                    log_msg(INFO, msg)
            except Exception:
                pass

    if vcenterip:
        cmd = "ping {} -c 3 -i 0.01".format(vcenterip)
        op = execmd(cmd)
        vcenter_check = pingstatus(op)

    # Update Test summary
    # vCenter Reachability check
    if vcenter_check == "FAIL":
        testsum[ip]["vCenter reachability check"] = {"Status": vcenter_check, "Result": "Check manually network connectivity."}
    else:
        testsum[ip]["vCenter reachability check"] = {"Status": vcenter_check, "Result": "Checks if vCenter is network reachable using PING."}
    # Timestamp check
    testsum[ip]["Timestamp check"] = {"Status": str(hostd[ip]["date check"]), "Result": "Checks if the timestamp is same across all Nodes."}
    # ntp source check
    if ntp_deamon_check == "PASS" and hostd[ip]["ntp source check"] == "PASS" and ntp_sync_check == "PASS":
        testsum[ip]["NTP sync check"] = {"Status": "PASS", "Result": "Checks if the NTP is synced with NTP server."}
    else:
        testsum[ip]["NTP sync check"] = {"Status": "FAIL", "Result": "Checks if the NTP is synced with NTP server."}
    # Check package & versions
    testsum[ip]["Check package & versions"] = {"Status": str(hostd[ip]["check package & versions"]), "Result": "Checks for count and version of HX packages on each node."}
    # Check Iptables count
    testsum[ip]["Check Iptables count"] = {"Status": str(hostd[ip]["check iptables"]), "Result": "Checks if the IP Table count matches on all nodes."}

    # 6) Check cluster usage
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

    # 7) Check cache is spread across all controller
    cmd = "nfstool -- -m | sort -u -k2"
    cachl = []
    op = execmd(cmd)
    for line in op:
        m = re.search(r"^\d+\s+([\d]{1,3}(.[\d]{1,3}){3})", line)
        if m:
            cachl.append(str(m.group(1)))

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
    snodes = len(eth1_list)
    nodecheck = "FAIL"
    if pnodes == snodes:
        nodecheck = "PASS"
    testsum[ip]["Extra pnodes check"] = {"Status": nodecheck, "Result": "Checks for any stale Node entry."}


    # 9) check packages and versions(Moved to Thread)

    # 10) check memory
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
    if check_memory == "FAIL":
        testsum[ip]["Memory usage check"] = {"Status": "FAIL", "Result": "Contact TAC"}
    else:
        testsum[ip]["Memory usage check"] = {"Status": check_memory, "Result": "Checks for available memory more than 2GB."}

    # 11) check CPU
    cmd = "top -b -n 1 | grep -B7 KiB"
    check_cpu = execmd(cmd)
    if not check_cpu:
        cmd = "top -b -n 1 | grep Cpu"
        check_cpu = execmd(cmd)

    # 12) check Out of memory
    cmd = "grep -ia 'out of memory' /var/log/kern.log"
    op = execmd(cmd)
    if op:
        if "Not able to run the command" in op:
            check_oom = ["No issue"]
            testsum[ip]["Incidence of OOM in the log file"] = {"Status": "PASS",
                                                               "Result": "Checks for any previous incidence of Out Of Memory Condition."}
        else:
            check_oom = op
            testsum[ip]["Incidence of OOM in the log file"] = {"Status": "FAIL",
                                                               "Result": "Checks for any previous incidence of Out Of Memory Condition."}
    else:
        check_oom = ["No issue"]
        testsum[ip]["Incidence of OOM in the log file"] = {"Status": "PASS",
                                                           "Result": "Checks for any previous incidence of Out Of Memory Condition."}

    # 13) ESXi supported upgrade
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
    testsum[ip]["Supported vSphere versions"] = {"Status": str("\n".join(svsp)), "Result": "Prints the supported ESXi versions."}

    # 14) Check permissions for /tmp
    cmd = "ls -ld /tmp"
    op = execmd(cmd)
    tmprcheck = ""
    for line in op:
        if line.startswith("drwxr-xrwx") or line.startswith("drwxrwxrwx"):
            tmprcheck = "PASS"
        else:
            tmprcheck = "FAIL"
    testsum[ip]["Check permissions for /tmp"] = {"Status": tmprcheck, "Result": "Checks if the /tmp permissions are set correctly."}

    # 15) Cluster Policy (Lenient/Strict) check
    cmd = "stcli cluster info | grep -i 'clusterAccessPolicy:' | head -1"
    op = execmd(cmd)
    clPolicy = ""
    for line in op:
        if "lenient" in line.lower():
            clPolicy = "Lenient"
            testsum[ip]["Check Cluster Policy"] = {"Status": "Lenient", "Result": "Checks the Configured Cluster Policy"}
        elif "strict" in line.lower():
            clPolicy = "Strict"
            testsum[ip]["Check Cluster Policy"] = {"Status": "Strict", "Result": "Please refer - https://tinyurl.com/yadvhd84"}

    # 16) Upgrade suggestion for HX version 2.1(1x)
    hxv = ""
    hxupsug = ""
    try:
        hxv = hostd[ip]["version"]
        m = re.search(r"2\.1[\.|(]1.", hxv)
        if m:
            hxupsug = "DO NOT direct upgrade to 3.5.2g.\nUpgrade to 3.5.2f first."
    except Exception:
        pass

    # 17) Different sector size check for HX version equal to 3.5.2a or < 3.0.1j
    hxsectchk = ""
    if "3.5.2a" in hxv:
        hxsectchk = "Do not perform node expansion or add drives (with HX-SD38TBE1NK9) before \nupgrading to higher versions"
    elif hxv.startswith("1.") or hxv.startswith("2."):
        hxsectchk = "Do not perform node expansion or add drives (with HX-SD38TBE1NK9) before \nupgrading to higher versions"
    else:
        m = re.search(r"3\.0\.1[a-j]", hxv)
        if m:
            hxsectchk = "Do not perform node expansion or add drives (with HX-SD38TBE1NK9) before \nupgrading to higher versions"

    # 18) Check springpath_keystore.jceks file [Run in Thread]
    keystoreCheck = str(hostd[ip]["check keystore"])
    if keystoreCheck == "FAIL":
        testsum[ip]["Check springpath_keystore.jceks file"] = {"Status": "FAIL", "Result": "If failed, contact Cisco TAC."}
    else:
        testsum[ip]["Check springpath_keystore.jceks file"] = {"Status": keystoreCheck, "Result": "All the SCVM have same keystore file."}

    # 19) SED Capable Check
    global lsusbCheck
    sedCapable = False
    usbCheck = False
    sedEnable = False
    sedDrive = False
    diskLock = ""
    cmd = "cat /etc/springpath/sed_capability.conf"
    op = execmd(cmd)
    for line in op:
        if "True" in line:
            sedCapable = True
    if sedCapable:
        testsum[ip]["SED Capable"] = {"Status": "YES", "Result": "Checks if the cluster is SED Capable."}
    else:
        testsum[ip]["SED Capable"] = {"Status": "NO", "Result": "Checks if the cluster is SED Capable."}

    if sedCapable:
        # 20) USB0 Check:
        cmd = "ifconfig | grep -i usb0 -A1 | grep 'inet addr' | cut -d ':' -f2 | cut -d ' ' -f1"
        op = execmd(cmd)
        if op:
            usbCheck = True
            testsum[ip]["USB0 check"] = {"Status": "PASS", "Result": "Checks for USB0 in SED clusters."}
        else:
            lsusbCheck = True
            testsum[ip]["USB0 check"] = {"Status": "FAIL", "Result": "Contact TAC"}

        # 21) SED AF Drives – 5100/5200 Check
        # Condition1 : Running 3.5(2a) and below
        # Condition2: Micron_5100 or Micron_5200 in /var/log/springpath/diskslotmap-v2.txt
        sflag1 = sflag2 = 0
        if "3.5.2a" in hxv:
            sflag1 = 1
        elif hxv.startswith("1.") or hxv.startswith("2."):
            sflag1 = 1
        elif hxv.startswith("3.5"):
            m1 = re.search(r"[1-3]\.[0-5]\.1[a-z]", hxv)
            if m1:
                sflag1 = 1
        else:
            m2 = re.search(r"3\.[0-4]", hxv)
            if m2:
                sflag1 = 1
        # Condition2: Micron_5100 or Micron_5200 in /var/log/springpath/diskslotmap-v2.txt
        cmd = "grep -E -- 'Micron_5100|Micron_5200' /var/log/springpath/diskslotmap-v2.txt"
        op = execmd(cmd)
        for line in op:
            if "Micron_5100" in line or "Micron_5200" in line:
                sflag2 = 1
        if sflag1 and sflag2:
            global sedNote
            sedNote = True
            testsum[ip]["SED AF Drives – 5100/5200 check"] = {"Status": "FAIL", "Result": "Please refer - https://tinyurl.com/vqnytww"}
        elif not sflag1 and sflag2:
            sedDrive = True
            testsum[ip]["SED AF Drives – 5100/5200 check"] = {"Status": "PASS", "Result": "Checks if Micron 5100/5200 drives in use."}

        # 22) SED Enabled Check:
        cmd = "cat /etc/springpath/sed.conf"
        op = execmd(cmd)
        for line in op:
            if "sed_encryption_state=enabled" in line:
                sedEnable = True
                testsum[ip]["SED Enabled"] = {"Status": "YES", "Result": "Checks if the cluster is SED Enabled."}
            else:
                testsum[ip]["SED Enabled"] = {"Status": "NO", "Result": "Checks if the cluster is SED Enabled."}

        # 23) Disk Locked Check:
        if sedEnable:
            cmd = "/usr/share/springpath/storfs-appliance/sed-client.sh -l | cut -d ',' -f5 | grep -a 1"
            op = execmd(cmd)
            if op:
                diskLock = "PASS"
                testsum[ip]["Disk Locked check"] = {"Status": "PASS", "Result": "Checks if any SED disk is locked."}
            else:
                diskLock = "FAIL"
                testsum[ip]["Disk Locked check"] = {"Status": "FAIL", "Result": "Checks if any SED disk is locked."}

    # Stretch Cluster check
    global stretchCluster
    witnessVmIp = ""
    witnessReachability = ""
    witnessLatetency = ""
    storageLatetency = ""
    if stretchCluster:
        # Get the Witness VM IP
        cmd = "stcli cluster info | grep dataZkIp"
        op = execmd(cmd)
        for line in op:
            m = re.search(r"([\d]{1,3}(.[\d]{1,3}){3})", line)
            if m:
                witnessVmIp = str(m.group(1))
        log_msg(INFO, "Witness VM IP Address: " + str(witnessVmIp) + "\r")

        # 24) Check Witness Reachability
        # Ping from eth0 to Witness VM IP Address
        if witnessVmIp:
            hostd[ip]["witnessVmIp"] = witnessVmIp
            eth0 = hostd[ip]["eth0"]
            cmd = "ping -I {} {} -c 3 -i 0.5".format(eth0, witnessVmIp)
            wop = execmd(cmd)
            witnessReachability = pingstatus(wop)
            testsum[ip]["Check Witness Reachability"] = {"Status": witnessReachability, "Result": "Checks Witness VM IP address is reachabile."}

            # 25) Check Witness Latetency
            # Ping Time should be less than 200ms
            for line in wop:
                if "round-trip" in line:
                    m = re.search(r"\/(\d+\.\d+)\sms$", line.strip())
                    if m:
                        pingTime = str(m.group(1))
                        try:
                            if float(pingTime) < 200:
                                witnessLatetency = "PASS"
                            else:
                                witnessLatetency = "FAIL"

                            # 26) Check Storage Latetency
                            # Ping Time should be less than 5ms
                            if float(pingTime) < 5:
                                storageLatetency = "PASS"
                            else:
                                storageLatetency = "FAIL"
                            testsum[ip]["Check Witness Latetency"] = {"Status": witnessLatetency,
                                                                      "Result": "Checks Witness VM IP address is latetency."}
                            testsum[ip]["Check Storage Latetency"] = {"Status": storageLatetency,
                                                                      "Result": "Checks Storage latetency."}
                        except Exception:
                            pass

    # 26) Check ZK-Cleanup-Script
    # Only for HX 4.0.2c
    zkstatus = ""
    try:
        if "4.0.2c" in hostd[ip]["version"]:
            cmd = "ps -aux | grep ZKTx | wc -l"
            op = execmd(cmd)
            if op:
                zkcnt = op[0]
                if zkcnt.isdigit():
                    if int(zkcnt) == 0:
                        zkstatus = "FAIL"
                    else:
                        zkstatus = "PASS"
            if zkstatus == "FAIL":
                testsum[ip]["Check ZK-Cleanup-Script"] = {"Status": zkstatus, "Result": "http://cs.co/9008HGXsy"}
            else:
                testsum[ip]["Check ZK-Cleanup-Script"] = {"Status": zkstatus, "Result": "Check to Identify multiple ZKTxnCleanup script."}
    except Exception:
        pass

    # 27) Run lsusb when USB0 Check Fails
    if lsusbCheck:
        cmd = "lsusb"
        op = execmd(cmd)

    # 28) Check Disk for SMART Failure
    cmd = """for D in $(/bin/lsblk -dpn -e 1,2,7,11 | awk '{ print $1 }'); do
                echo $D | grep -q nvme
                if [ $? -eq 0 ]; 
                then
                STATUS=$(/usr/sbin/nvme smart-log $D 2> /dev/null |
                awk -F': ' '/critical_warning/ { print $NF }')
                else
                /usr/sbin/smartctl -q silent -H -i $D;
                STATUS=$?
                STATUS=$((STATUS & 26))
                fi
                echo "$D: $STATUS";
                done"""
    diskList = execmd(cmd)
    smartFailDiskList = []
    for disk in diskList:
        if "0" not in disk:
            smartFailDiskList.append(disk)
    if smartFailDiskList:
        testsum[ip]["Check Disk for SMART Failure"] = {"Status": "FAIL", "Result": "Contact TAC"}
    else:
        testsum[ip]["Check Disk for SMART Failure"] = {"Status": "PASS", "Result": "Checking Disk for SMART Failure"}

    # Check hxuser password
    testsum[ip]["Check hxuser password characters"] = {"Status": str(hostd[ip]["check hxuser password"]), "Result": "Checking  hxuser password characters"}

    #####################################################
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
    # Cluster Upgrade Status: Removed
    # No extra pnodes
    testdetail[ip]["Pre-Upgrade check"]["No extra pnodes"] = nodecheck
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
    if hxupsug != "":
        testdetail[ip]["Pre-Upgrade check"]["Upgrade suggestion for HX version 2.1(1x)"] = hxupsug
    if hxsectchk != "":
        testdetail[ip]["Pre-Upgrade check"]["Different sector size check"] = hxsectchk
    # Cluster Policy (Lenient/Strict) check
    if clPolicy == "Strict":
        testdetail[ip]["Pre-Upgrade check"]["Cluster Policy check"] = {"Status": "Strict", "Result": "Please refer - https://tinyurl.com/yadvhd84"}
    else:
        testdetail[ip]["Pre-Upgrade check"]["Cluster Policy check"] = clPolicy
    # Check springpath_keystore.jceks file
    testdetail[ip]["Pre-Upgrade check"]["Check springpath_keystore.jceks file"] = str(hostd[ip]["check keystore"])
    # SED Capable Check:
    if sedCapable:
        testdetail[ip]["Pre-Upgrade check"]["SED Capable"] = "YES"
        if usbCheck:
            testdetail[ip]["Pre-Upgrade check"]["USB0 check"] = "PASS"
        else:
            testdetail[ip]["Pre-Upgrade check"]["USB0 check"] = {"Status": "FAIL", "Result": "Contact TAC"}
    else:
        testdetail[ip]["Pre-Upgrade check"]["SED Capable"] = "NO"
    # SED AF Drives – 5100/5200 Check
    if sedNote:
        testdetail[ip]["Pre-Upgrade check"]["SED AF Drives – 5100/5200 check"] = {"Status": "FAIL", "Result": "Please refer - https://tinyurl.com/vqnytww"}
    if sedDrive:
        testdetail[ip]["Pre-Upgrade check"]["SED AF Drives – 5100/5200 check"] = "PASS"
    # SED Enabled Check:
    if sedEnable:
        testdetail[ip]["Pre-Upgrade check"]["SED Enabled"] = "YES"
        testdetail[ip]["Pre-Upgrade check"]["Disk Locked check"] = diskLock
    # Stretch Cluster Check
    if witnessVmIp:
        testdetail[ip]["Pre-Upgrade check"]["Check Witness Reachability"] = {"Status": witnessReachability, "Result": "Checks Witness VM IP address is reachabile."}
        testdetail[ip]["Pre-Upgrade check"]["Check Witness Latetency"] = {"Status": witnessLatetency, "Result": "Checks Witness VM IP address is latetency."}
        testdetail[ip]["Pre-Upgrade check"]["Check Storage Latetency"] = {"Status": storageLatetency, "Result": "Checks Storage latetency."}
    # Check ZK-Cleanup-Script
    if zkstatus:
        if zkstatus == "FAIL":
            testdetail[ip]["Pre-Upgrade check"]["Check ZK-Cleanup-Script"] = {"Status": zkstatus, "Result": "http://cs.co/9008HGXsy"}
        else:
            testdetail[ip]["Pre-Upgrade check"]["Check ZK-Cleanup-Script"] = {"Status": zkstatus, "Result": "Check to Identify multiple ZKTxnCleanup script."}
    # Check Disk for SMART Failure
    if smartFailDiskList:
        testdetail[ip]["Pre-Upgrade check"]["Check Disk for SMART Failure"] = {"Status": "FAIL", "Result": "\n".join(smartFailDiskList)}
    else:
        testdetail[ip]["Pre-Upgrade check"]["Check Disk for SMART Failure"] = "PASS"
    # Check hxuser password
    testdetail[ip]["Pre-Upgrade check"]["Check hxuser password characters"] = str(hostd[ip]["check hxuser password"])

def network_check(ip):
    # Network Check(ESX)
    try:
        # Close connection
        client.close()
    except Exception:
        pass
    esxip = hostd[ip]["esxip"]
    esx_version = ""
    try:
        if esxip != "":
            # Initiate SSH Connection
            client.connect(hostname=esxip, username=hxusername, password=esxpassword, timeout=time_out)
            msg = "\r\nSSH connection established to ESX Host: " + esxip + "\r"
            log_msg(INFO, msg)

            # Get all ESX and Storage Controller IP Address
            opd = OrderedDict()
            nwtestsum[esxip] = OrderedDict()
            nwtestdetail[esxip] = OrderedDict()

            # 1) Check hx user created
            hxac = ""
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

            # 2) Check vMotion Enabled
            vmst = esx_vmotion[esxip]["vmotion"]
            opd.update({"vMotion Enabled": vmst})

            # 3) Check vMotion reachability check
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
                            cmd = "vmkping -I {} -c 3 -d -s {} -i 0.5 {}".format(vmknode, mtu, vmkip)
                            op = execmd(cmd)
                            pst = pingstatus(op)
                            opd.update({cmd: pst})
                            allvmkpingchk.append(pst)
                        except Exception:
                            pass

            # 4) Check ESXi Version
            try:
                cmd = "vmware -l"
                op = execmd(cmd)
                opd.update({"ESX Version": op})
                v = op[0]
                m = re.search(r"ESXi (\d\.\d)", v)
                if m:
                    esx_version = m.group(1)
            except Exception:
                pass

            # 5) ESX vib list
            vibl = []
            try:
                #cmd = "esxcli software vib list| grep -i spring"
                cmd = "esxcli software vib list| egrep -i 'scvm|stHyper|stfs'"
                op = execmd(cmd)
                for line in op:
                    vibl.append(line.replace(" "*26, "    "))
                opd.update({"ESX Vib List": vibl})
            except Exception:
                pass

            # 6) Check SCVM and STFSNasPlugin version: Removed

            # 7) ESX Services
            try:
                cmd = "chkconfig --list | grep -E 'ntpd|hostd|vpxa|stHypervisorSvc|scvmclient|hxctlvm'"
                op = execmd(cmd)
                opd.update({"ESX Services": op})
            except Exception:
                pass

            # 8) Check for HX down during upgrade
            check_HX_down_status = ""
            try:
                if esx_version and float(esx_version) >= 6.7:
                    # ESXi 6.7 and above
                    cmd = "netdbg vswitch runtime get | grep TeamPolicyUpDelay -A2 | cut -d ':' -f2"
                    op = execmd(cmd)
                    if op:
                        v = op[0]
                        v = v.strip()
                        if v.isdigit():
                            if int(v) < 30000:
                                check_HX_down_status = "FAIL"
                            else:
                                check_HX_down_status = "PASS"
                else:
                    # ESXi 6.5 and lower
                    cmd = "esxcli system settings advanced list | grep TeamPolicyUpDelay -A2 | grep Int | cut -d ':' -f2 | cut -d ' ' -f2"
                    op = execmd(cmd)
                    if op:
                        v = op[0]
                        v = v.strip()
                        if v.isdigit():
                            if int(v) < 30000:
                                check_HX_down_status = "FAIL"
                            else:
                                check_HX_down_status = "PASS"
                opd["Check for ESXI Failback timer"] = check_HX_down_status
            except Exception:
                pass

            # 9) vmk1 ping to each SCVM eth1
            vmk1 = ""
            mtu = "1472"
            try:
                vmk1 = hostd[ip]["vmk1"]
                mtu = vmk1_mtu[vmk1]["mtu"]
            except Exception:
                if esxip in compute_vmk0_list:
                    vmk1 = esxip
                    # Get MTU
                    try:
                        cmd = "esxcfg-vmknic -l"
                        op = execmd(cmd)
                        for line in op:
                            if vmk1 in line and "IPv4" in line:
                                if " 1500 " in line:
                                    mtu = "1472"
                                elif " 9000 " in line:
                                    mtu = "8972"
                    except Exception as e:
                        log_msg(ERROR, str(e) + "\r")
            vmkpingchk = []
            if len(eth1_list) > 0 and vmk1:
                for k in eth1_list:
                    try:
                        cmd = "vmkping -I {} -c 3 -d -s {} -i 0.5 {}".format("vmk1", mtu, k)
                        op = execmd(cmd)
                        pst = pingstatus(op)
                        opd.update({cmd: pst})
                        vmkpingchk.append(pst)
                    except Exception:
                        pass

            # 10) vSwitch info of ESXi
            try:
                cmd = "esxcfg-vswitch -l"
                op = execmd(cmd)
                cm = "esxcfg-vswitch -l"
                opd.update({cm: op})
            except Exception:
                pass

            # 11) Check extra contoller vm folders
            vmfld = ""
            try:
                cmd = "esxcli hardware platform get | grep -i serial"
                op = execmd(cmd)
                srno = ""
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

            # 12) VMware Tools location check:
            vmtoolcheck = ""
            try:
                cmd = "esxcli system settings advanced list -o /UserVars/ProductLockerLocation | grep -i 'string value'"
                op = execmd(cmd)
                svalue = ""
                dsvalue = ""
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

            # 13) vfat Disk Usage check
            vfatcheck = "PASS"
            try:
                cmd = "df -h | grep vfat | grep 100%"
                op = execmd(cmd)
                for line in op:
                    if "100%" in line:
                        vfatcheck = "FAIL"
                        break
                opd.update({"vfat Disk Usage check": vfatcheck})
            except Exception:
                pass

            # 14) Check /tmp usage
            tmpUsageCheck = ""
            try:
                cmd = "vdf | grep tmp"
                op = execmd(cmd)
                for line in op:
                    if "tmp" in line:
                        m = re.search(r"\s(\d+)%\s", line)
                        if m:
                            usg = m.group(1)
                            if int(usg) <= 80:
                                tmpUsageCheck = "PASS"
                            else:
                                tmpUsageCheck = "FAIL"
                opd.update({"Check /tmp usage": tmpUsageCheck})
            except Exception:
                pass

            # 15) Micron 5100 Drive Firmware Check
            mfwcheck = ""
            micronbug = ""
            try:
                cmd = "esxcli storage core device list"
                op = execmd(cmd)

                mflag1 = mflag2 = 0
                for line in op:
                    if "Model:" in line and "Micron_5100" in line:
                        mflag1 = 1
                        mflag2 = 0
                        mfwcheck = "PASS"
                        continue
                    elif mflag1 == 1 and "Revision:" in line:
                        mflag1 = 0
                        mflag2 = 1
                    if mflag2 == 1 and "U049" in line:
                        micronbug = "Please Refer: https://tinyurl.com/vqnytww"
                        mfwcheck = "FAIL"
                        break
                if micronbug != "":
                    opd.update({"Micron 5100 Drive Firmware Check": micronbug})
            except Exception:
                pass

            # 16) Run lsusb when USB0 Check Fails
            global lsusbCheck
            if lsusbCheck:
                try:
                    cmd = "lsusb"
                    op = execmd(cmd)
                except Exception:
                    pass

            # Update Test Detail
            nwtestdetail.update({esxip: opd})
            # Close connection
            client.close()

            # Test summary
            # HX User Account check
            nwtestsum[esxip]["HX User Account check"] = {"Status": hxac, "Result": "Checks if HXUSER is present."}
            # vMotion enabled check
            nwtestsum[esxip]["vMotion enabled check"] = {"Status": esx_vmotion[esxip]["vmotion"], "Result": "Checks if vMotion is enabled on the host."}
            # vMotion reachability check: Removed
            # Check for HX down during upgrade
            #nwtestsum[esxip]["Check for HX down during upgrade"] = check_HX_down_status[:4]
            if check_HX_down_status == "FAIL":
                nwtestsum[esxip]["Check for ESXI Failback timer"] = {"Status": check_HX_down_status,
                                                                     "Result": "If Failed, Change the failback timer to 30secs:" + "\na)For ESXi 6.5: 'esxcfg-advcfg -s 30000 /Net/TeamPolicyUpDelay'\nb)For ESXi 6.7: 'netdbg vswitch runtime set TeamPolicyUpDelay 30000'"}
            else:
                nwtestsum[esxip]["Check for ESXI Failback timer"] = {"Status": check_HX_down_status, "Result": "Checks for ESXi FAILBACK timer set to 30000ms."}
            # Check vmk1 ping to eth1
            if vmkpingchk:
                if "FAIL" in vmkpingchk:
                    nwtestsum[esxip]["Check vmk1 ping to eth1"] = {"Status": "FAIL",
                                                                   "Result": "If Failed, Perform manual vmkping between ESXi vmk1 and SCVM eth1."}
                else:
                    nwtestsum[esxip]["Check vmk1 ping to eth1"] = {"Status": "PASS",
                                                                  "Result": "Checks Network between ESXi vmk1 and SCVM eth1."}
            # No extra controller vm folders check
            nwtestsum[esxip]["No extra controller vm folders check"] = {"Status": vmfld[:4], "Result": "Checks for duplicate Controller SCVM Folders."}
            # VMware Tools location check
            nwtestsum[esxip]["VMware Tools location check"] = {"Status": vmtoolcheck, "Result": "Checks for Non default VMware Tools location."}
            # vfat Disk Usage check
            nwtestsum[esxip]["vfat Disk Usage check"] = {"Status": vfatcheck, "Result": "Checks for vfat Disk Usage."}
            # Check /tmp usage
            if tmpUsageCheck == "FAIL":
                nwtestsum[esxip]["Check /tmp usage"] = {"Status": tmpUsageCheck, "Result": "Please ensure usage of /tmp is less than 80%."}
            else:
                nwtestsum[esxip]["Check /tmp usage"] = {"Status": tmpUsageCheck, "Result": "Checking for /tmp usage."}
            # Micron 5100 Drive Firmware Check
            if mfwcheck:
                nwtestsum[esxip]["Micron 5100 Drive Firmware Check"] = {"Status": mfwcheck, "Result": micronbug}

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
        print("\r\nSCVM eth0: " + ", ".join(eth0_list) + "\r")
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
        print("\r\nSCVM eth0: " + ", ".join(eth0_list) + "\r")
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


def create_main_report(clusterName, clusterType):
    global sedflag
    # create main report file
    filename = "HX_Tool_Main_Report_" + get_date_time() + ".txt"
    with open(filename, "w") as fh:
        fh.write("\t\t\tHX Health Check " + str(toolversion))
        fh.write("\r\n")
        fh.write("\t\t\t:HX Tool Main Report:")
        fh.write("\r\n")
        fh.write("#" * 80)
        fh.write("\r\n")
        fh.write("\r\nCluster Name: " + str(clusterName.strip()))
        fh.write("\r\n")
        fh.write("\r\nCluster Type: " + str(clusterType.strip()).upper())
        fh.write("\r\n")
        fh.write("\r\nHX Cluster Nodes:")
        fh.write("\r\n")
        fh.write((str(ht)).replace("\n", "\r\n"))
        fh.write("\r\n")
        fh.write("\r\n")

        # Each HX Node Report
        for ip in hxips:
            fh.write("\r\n")
            fh.write("#" * 80)
            fh.write("\r\n")
            fh.write("\t\t\tHX Controller: " + ip)
            fh.write("\r\n")
            fh.write("\t\t\tHX Hostname: " + hostd[ip].get("hostname", ""))
            fh.write("\r\n")
            fh.write("#" * 80)
            fh.write("\r\n")
            n = 1
            try:
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
            except Exception:
                continue
    with open(filename, "a") as fh:
        fh.write("\r\n")
        fh.write("#" * 80)
        fh.write("\r\n")
        fh.write("\r\n\t\t\t Network check:" + "\r")
        fh.write("\r\n")
        fh.write("#" * 80)
        fh.write("\r\n")
        fh.write("vmk0: " + ", ".join(esx_hostsl))
        fh.write("\r\n")
        fh.write("vmk1: " + ", ".join(vmk1_list))
        fh.write("\r\n")
        fh.write("eth0: " + ", ".join(eth0_list))
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
        fh.write("1) If upgrading to HX 4.0(2a), please review the following link and perform workaround – https://tinyurl.com/wc7j5qp" + "\r\n")
        fh.write("2) Please check the status of Compute nodes manually, script only verifies the config on the converged nodes." + "\r\n")
        fh.write("3) Hypercheck doesnot perform FAILOVER TEST, so please ensure that the upstream is configured for network connectivity for JUMBO or NORMAL MTU size as needed." + "\r\n")
        if sedNote:
            fh.write("4) SED Drive Failure Might Cause Cluster to Go Down -  https://www.cisco.com/c/en/us/support/docs/field-notices/702/fn70234.html" + "\r\n")
        fh.write("\r\n")
    print("\r\nMain Report File: " + filename)
    log_stop()
    create_tar_file()
    print("\r\nRelease Notes:")
    print("\rhttps://www.cisco.com/c/en/us/support/hyperconverged-systems/hyperflex-hx-data-platform-software/products-release-notes-list.html")
    print("\r\nUpgrade Guides:")
    print("\rhttps://www.cisco.com/c/en/us/support/hyperconverged-systems/hyperflex-hx-data-platform-software/products-installation-guides-list.html")
    print("\r\nNote:")
    print("\r1) If upgrading to HX 4.0(2a), please review the following link and perform workaround – https://tinyurl.com/wc7j5qp")
    print("\r2) Please check the status of Compute nodes manually, script only verifies the config on the converged nodes.")
    print("\r3) Hypercheck doesnot perform FAILOVER TEST, so please ensure that the upstream is configured for network connectivity for JUMBO or NORMAL MTU size as needed.")
    if sedNote:
        print("\r4) SED Drive Failure Might Cause Cluster to Go Down -  https://www.cisco.com/c/en/us/support/docs/field-notices/702/fn70234.html")
    print("\r\n")


def create_json_file(clusterName, clusterType):
    filename = "HX_Tool_Summary.json"
    data = {}
    data["Cluster Name"] = str(clusterName.strip())
    data["Cluster Type"] = str(clusterType.strip())
    data["HX Checks"] = testsum
    data["NW Checks"] = nwtestsum
    with open(filename, "w") as fh:
        json.dump(data, fh)

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

    # Arguments passed
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
    hxcdt = datetime.datetime.now()
    bdt = datetime.datetime.strptime(builddate, "%Y-%m-%d")
    ndays = (hxcdt - bdt).days
    if int(ndays) >= 30:
        print("\n    The script in use might be old. Please check and confirm that this is the latest script on Github.")
    # HX Controller parameter
    print("\nPlease enter below info of HX-Cluster:")
    hxusername = "root"
    log_msg(INFO, "Username: " + hxusername + "\r")
    hxpassword = getpass.getpass("Enter the HX-Cluster Root Password: ")
    esxpassword = getpass.getpass("Enter the ESX Root Password: ")
    port = 22
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

    # Get Cluster Name
    print("")
    clustername = ""
    clusterType = ""
    cmd = "stcli cluster storage-summary --detail | grep -i name | cut -d: -f2"
    op = runcmd(cmd)
    if "Not able to run the command" in op:
        pass
    else:
        clustername = op.strip()
    log_msg(INFO, "Cluster Name: " + str(clustername) + "\r")
    log_msg("", "Cluster Name: " + str(clustername) + "\r")

    # Get Cluster Type
    cmd = "stcli cluster info | grep -i clustertype | head -1 | cut -d: -f2"
    op = runcmd(cmd)
    if op:
        clusterType = op.strip()

    # Check Stretch Cluster
    stcnt = ""
    cmd = "find / -name stretch* | wc -l"
    cop = runcmd(cmd)
    if "Not able to run the command" in cop:
        pass
    else:
        stcnt = cop.strip()
        if stcnt.isdigit():
            if int(stcnt) > 0:
                clusterType = "STRETCH_CLUSTER"
    log_msg(INFO, "Cluster Type: " + str(clusterType) + "\r")
    if clusterType:
        print("")
        log_msg("", "Cluster Type: " + str(clusterType).upper() + "\r")
    # Set Stretch Cluster
    stretchCluster = False
    if "stretch" in clusterType.lower():
        stretchCluster = True

    # Get Controller Mgmnt IP Addresses
    # Old cmd used to get controller IP Addresses
    # cmd1 = "stcli cluster info | grep -i  stctl_mgmt -n1 | grep -i addr"
    # Get eth1 ips
    cmd = "sysmtool --ns cluster --cmd info | grep -i uuid"
    op = runcmd(cmd)
    ips = []
    if op:
        ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", op)
    if not ips:
        print("HX Nodes IP Addresses are not found")
        sys_exit(0)
    ips.sort(key=lambda ip: map(int, reversed(ip.split('.'))))
    log_msg(INFO, "IP Adresses: " + ", ".join(ips) + "\r")
    eth1_list = list(ips)
    eth1_list.sort(key=lambda ip: map(int, reversed(ip.split('.'))))

    # Get all hostnames
    hostd = {}
    subreportfiles = []
    print("")
    # global sedflag

    #############################################################
    # Get Controller eth0 ips or storage controller ips
    hxips = []
    eth0_list = []
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
        time.sleep(35)
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

    ht = PrettyTable(hrules=ALL)
    ht.field_names = ["Nodes", "IP Address", "HostName"]
    ht.align = "l"
    for i, ip in enumerate(hxips):
        ht.add_row([i + 1, hostd[ip].get("eth0", ""), hostd[ip].get("hostname", "")])
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

    # Check keystore file
    keystoreCheck = ""
    keystoreList = []
    for ip in hostd.keys():
        keystore = hostd[ip]["keystore"]
        if keystore not in keystoreList:
            keystoreList.append(keystore)
    if len(keystoreList) == 1:
        keystoreCheck = "PASS"
    else:
        keystoreCheck = "FAIL"
    for ip in hostd.keys():
        hostd[ip]["check keystore"] = keystoreCheck

    # Check hxuser password having special character
    hxpsdcheck = ""
    try:
        cmd = "/opt/springpath/storfs-support/getEsxConnectionInfo.sh"
        op = runcmd(cmd, False)
        if "password" in op:
            p = re.search(r"password\":\s+\"(.+)\"", op)
            if p:
                psd = p.group(1)
                if re.search(r"(\{[\{\#\%])|//|\\\\|'|\"", psd):
                    hxpsdcheck = "FAIL"
                else:
                    hxpsdcheck = "PASS"
    except Exception:
        pass
    for ip in hostd.keys():
        hostd[ip]["check hxuser password"] = hxpsdcheck

    # Get ESX IPs, vmk1 ips
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
    esx_vmotion = {}
    vmk1_mtu = {}
    vmk1_list = []
    for ip in esx_hostsl:
        esx_vmotion[str(ip)] = dict.fromkeys(["vmotion", "vmkip", "mtu"], "")

    # Get all vmk1 using threads
    threads = []
    for ip in hostd.keys():
        th = threading.Thread(target=get_vmk1, args=(ip, hxusername, esxpassword, time_out,))
        th.start()
        time.sleep(5)
        threads.append(th)

    for t in threads:
        t.join()

    vmk1_list = [v for v in vmk1_list if v != " "]
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
    testsum = OrderedDict()
    testdetail = OrderedDict()
    nwtestsum = OrderedDict()
    nwtestdetail = OrderedDict()
    # Bug details table
    bugs = {
        "HX down": "HX cluster goes down during the UCS infra upgrade. This is because of the default failback delay interval(10sec) on ESXi." + "\nDefault Value - 10sec" + "\nModify to - 30sec"
    }

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
            pbar.stop("COMPLETED")
            log_msg(INFO, "Progressbar Stopped" + "\r")

            # 2. ZooKeeper and Exhibitor check
            # Progressbar
            pbar = ProgressBarThread()
            pbar.start("ZooKeeper & Exhibitor check")
            log_msg(INFO, "Progressbar Started" + "\r")
            zookeeper_check(ip)
            # stop progressbar
            pbar.stop("COMPLETED")
            log_msg(INFO, "Progressbar Stopped" + "\r")

            # 3. HDD health check
            # Progressbar
            pbar = ProgressBarThread()
            pbar.start("HDD health check           ")
            log_msg(INFO, "Progressbar Started" + "\r")
            hdd_check(ip)
            # stop progressbar
            pbar.stop("COMPLETED")
            log_msg(INFO, "Progressbar Stopped" + "\r")

            # 4. Pre-Upgrade Check
            # Progressbar
            pbar = ProgressBarThread()
            pbar.start("Pre-Upgrade Check          ")
            log_msg(INFO, "Progressbar Started" + "\r")
            pre_upgrade_check(ip)
            # stop progressbar
            pbar.stop("COMPLETED")
            log_msg(INFO, "Progressbar Stopped" + "\r")

            # 5. Network Summary
            # Progressbar

            pbar = ProgressBarThread()
            pbar.start("Network check              ")
            log_msg(INFO, "Progressbar Started" + "\r")
            network_check(ip)
            # stop progressbar
            pbar.stop("COMPLETED")
            log_msg(INFO, "Progressbar Stopped" + "\r")

            # Close connection
            client.close()

            # Create report file
            #create_sub_report(ip)

        except KeyboardInterrupt:
            sys_exit(0)

        except Exception as e:
            msg = "\r\nNot able to establish SSH connection to HX Node: " + ip + "\r"
            log_msg(INFO, msg)
            # log_msg("", msg)
            log_msg(ERROR, str(e) + "\r")
            # sys_exit(0)
            # stop progressbar
            pbar.stop("INCOMPLETE")
            log_msg(INFO, "Progressbar Stopped" + "\r")
            continue

    ###############################################################

    # Display the test result
    display_result()

    # Create Test Summary json file
    create_json_file(clustername, clusterType)

    # Create Main Report File
    create_main_report(clustername, clusterType)

    # End
    sys.exit(0)
