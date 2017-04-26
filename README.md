# XenMobileBP
Container for XM Environment Data Gathering 

The goal of this project to is pull configuration infromation from your XMS server and NetScaler.  The script will then detect common issues with your configuration and provide an HTML report at the end for easy viewing and assessment.  

This project leverages Docker, XenMobile, NetScaler, PowerShell, XMS REST and NetScaler Nitro/REST APIs.

To get started, we assume you have docker already installed and that you are on Mac/OS X.  The container and Dockerfile are cross platform.  The config.sh, setup.sh and report.sh will need to be ported if you are on an MS Windows system as they are bash scripts.

1. Create a directory to store our content needed to run.  (mkdir NewDirName)
2. cd to the new directory.  (cd NewDirName)
3. Download Dockerfile, setup.sh and report.sh from the releases link (at the top of this page) to our newly created directory.
4. cd to the new directory in a terminal window if you are not already there.
5. Modify config.sh with your environments login information, hostnames, etc.  The settings in this file are used by both setup.sh and report.sh
6. chmod the scripts so that we can execute them:
6. chmod +x setup.sh
6. chmod +x report.sh
6. chmod +x config.sh
6. Run setup.sh  This will create our XenMobileBP docker container, download and install the Nitro REST APIs, download the latest version our our script and create the report.
7. Verify that the report was created in the working folder.  It should contain an HTML file titled "test.htm".  Double click the file and verify results.
8. Run the following command if you plan to debug the xmChecker.ps1 script on an OS X machine.  This is optional.  This will take a few minutes to compile and install.  The scripts assumes connections on https/443.   brew install curl --with-openssl
9. Run the following command if you plan to debug on an OS X machine.  This is optional.  Run the following command:   brew link --force curl

```diff
- The Release link should be at the top of this page.  
- This is the URL if you received this file from a zip, etc.  https://github.com/mbbowlin/XenMobileBP
```

Note:  Windows users will need to port the setup.sh script to meet thier needs.

Running the setup.sh script repeatedly will create multiple xemobilebp container images.  So setup.sh should not be run unless you need to create or update your image.

Admins should run "report.sh" for iterative runs of the report after the initial setup.sh run.

This projects builds upon the work done by Esther Barthel with CognitionIT.  ( https://github.com/cognitionIT ) We borrowed some of their Nitro PowerShell wrappers in our script.  
