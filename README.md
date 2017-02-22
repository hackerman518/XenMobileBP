# XenMobileBP
XnMobileBP is a Docker container for monitoring a XenMobile enviornment for best practice settings and reporting.  

The goal of this project to is pull configuration infromation from your XMS server and NetScaler.  The script will then detect common issues with your configuration and provide an HTML report at the end for easy viewing and assessment.  

This project leverages Docker, XenMobile, NetScaler, PowerShell, XMS REST and NetScaler Nitro/REST APIs.

To get started, we assume you have docker already installed and that you are on Mac/OS X.  The container and Dockerfile is cross platform.  The script to launch will need to be ported to windows as it is a bash script.

1. Create a directory to store our content needed to run.  (mkdir NewDirName)
2. cd to the new directory.  (cd NewDirName)
3. Download Dockerfile, setup.sh and report.sh from the releases link to our newly created directory.
4. cd to the new directory in a terminal window if you are not already there or did it in Finder.
5. Modify setup.sh and report.sh with your environments login information, hostnames, etc.
6. chmod +x setup.sh
6. chmod +x report.sh
6. Run setup.sh  This will create our XenMobileBP docker container, download and install the Nitro REST APIs, download the latest version our our script and create the report.
7. To verify our output, our folder should contain an HTML file titled "test.htm".  Double click the file and verify results.

```diff
- The Release link should be at the top of this page.  
- This is the URL if you received this file from a zip, etc.  https://github.com/mbbowlin/XenMobileBP
```

Note:  Windows users will need to port the setup.sh script to meet thier needs.

Running the setup.sh script repeatedly will create multiple xemobilebp container images.  So setup.sh should not be run unless you need to create or update your image.

Admins should run "report.sh" for iterative runs of the report after the initial setup.sh run.

This projects builds upon the work done by Esther Barthel with CognitionIT.  ( https://github.com/cognitionIT ) We borrowed some of their Nitro PowerShell wrappers in our script.  
