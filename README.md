# XenMobileBP
XnMobileBP is a Docker container for monitoring a XenMobile enviornment for best practice settings and reporting.  

The goal of this project to is pull configuration infromation from your XMS server and NetScaler.  The script will then detect common issues with your configuration and provide an HTML report at the end for easy viewing and assessment.  

This project leverages Docker, XenMobile, NetScaler, PowerShell, XMS REST and NetScaler Nitro/REST APIs.

To get started, we assume you have docker already installed.

1.  Download Dockerfile from the releases page.
