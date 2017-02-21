### Get the base ubunto:xenial container build
#FROM microsoft/dotnet:1.0-runtime-deps
FROM microsoft/powershell
MAINTAINER Mike Bowlin <Mike.Bowlin@Citrix.com>

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install .NET Core
#ENV DOTNET_VERSION 1.0.3
#ENV DOTNET_DOWNLOAD_URL https://dotnetcli.blob.core.windows.net/dotnet/preview/Binaries/$DOTNET_VERSION/dotnet-debian-x64.$DOTNET_VERSION.tar.gz

#RUN curl -SL $DOTNET_DOWNLOAD_URL --output dotnet.tar.gz \
#    && mkdir -p /usr/share/dotnet \
#    && tar -zxf dotnet.tar.gz -C /usr/share/dotnet \
#    && rm dotnet.tar.gz \
#    && ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet

# Set Environment Variable to Get latest xmChecker Script

ENV XM_CHECKER_VERION -v0.01
ENV XM_CHECKER_NAME xmChecker
ENV CHECKER_DOWNLOAD_URL https://github.com/mbbowlin/XenMobileBP/blob/master/$XM_CHECKER_NAME$XM_CHECKER_VERION.ps1
ENV CHECKER_DOWNLOAD_URL https://github.com/mbbowlin/XenMobileBP/releases/download/v0.01-alpha/xmChecker-v0.01.ps1

### Setup the basic system the way we want it.
RUN mkdir /XenMobile \
    && cd /XenMobile \ 
    && curl -SL $CHECKER_DOWNLOAD_URL --output $XM_CHECKER_NAME$XM_CHECKER_VERION.ps1 


### Set our working directory
ENV WORKDIR /XenMobile

### Setup environment variables ro Download PowerShell
#ENV POWERSHELL_VERSION v6.0.0-alpha.16
#ENV CPUARCHITECTURE amd64
#ENV POWERSHELL_DOWNLOAD_URL https://github.com/PowerShell/PowerShell/releases/download/v$POWERSHELL_VERSION/powershell_$POWERSHELL_VERSION-1ubuntu1.16.04.1_$CPUARCHITECTURE.deb


## Get latest download builds from here:  https://github.com/PowerShell/PowerShell/releases/  Example below.
#https://github.com/PowerShell/PowerShell/releases/download/v6.0.0-alpha.16/powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
#ENV POWERSHELL_DOWNLOAD_URL https://github.com/PowerShell/PowerShell/releases/download/v6.0.0-alpha.16/powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb

#RUN curl -SL $POWERSHELL_DOWNLOAD_URL --output powershell.deb \
#    && dpkg --install powershell.deb 
#    && rm powershell.deb \
#    && apt-get clean

ENTRYPOINT ["powershell"]

### next we will run 
#  use docker build --help for more info.
#  docker build  --tag XenMobileBP --no-cache . 