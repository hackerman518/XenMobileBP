# XenMobileBP
XnMobileBP is a Docker container for monitoring a XenMobile enviornment for best practice settings and reporting.  

The goal of this project to is pull configuration infromation from your XMS server and NetScaler.  The script will then detect common issues with your configuration and provide an HTML report at the end for easy viewing and assessment.  

This project leverages Docker, XenMobile, NetScaler, PowerShell, XMS REST and NetScaler Nitro/REST APIs.

To get started, we assume you have docker already installed.

1. Create a directory to store our content needed to run.  
2. Download Dockerfile from the releases page to our newly created directory.
3. Modify setup.sh with your environments login information.
4. Run setup.sh  This will create our XenMobileBP docker container, download and install the Nitro REST APIs, download the latest version our our script and create the report.
5. To verify our output, our folder should contain an HTML file titled "test.htm".  Double click the file and verify results.

Note:  Windows users will need to port the setup.sh script to meet thier needs.

Running the setup.sh script repeatedly will create multiple xemobilebp container images.  So should not be run unless you need to update your image.

Admins should run "report.sh" for iterative runs of the report.
