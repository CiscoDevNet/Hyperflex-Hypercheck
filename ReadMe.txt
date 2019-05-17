Introduction

• The Hypercheck tool is a utility to perform pro-active self checks on Hypoerflex clusters to ensure its stability and resiliency.
• It also helps perform automated pre-upgrade checks to have a better upgrade experience.
• The tool automates a list of checks on Hyperflex System saving time during Maintenance activity and Upgrade processes.

Supported HX Versions
    2.6
    3.0
    3.5
    4.0

Supported HX Clusters
    Hyperflex Standard Cluster
    Hyperflex Edge Cluster (3Node and 4Node)
    Only supported on Hyperflex cluster on VMWare ESXi

When to use?
    Before Hyperflex upgrades.
    Hyperflex Health Check before and after Maintenance Windows
    When working with Cisco TAC
    Pro-active Health Check anytime.

How to use the tool?
Pre-requisite:  Script needs HX and ESXI root password information to check all conditions

Steps:
1) Download the tool(HXTool.py) and upload to the controller VM (preferably HX Cluster Management IP).

2) Now run the python script file with below command:
   a) For Test summary report:
      python HXTool.py
   b) For Test detail report:
      python HXTool.py detail
3) Enter the HX root password.
4) Enter the ESXi root password.
5) Script will display the result on the console and also creates each node report(HX Report 10.X.X.79.txt) and main report txt file(HX Tool Main Report.txt) in the HX_Report_<timestamp> folder.

Test Details:
Detail info of the test are available in the file(TestInfo.txt).
