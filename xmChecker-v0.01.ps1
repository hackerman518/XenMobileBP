#========================================================================================
#  Example PowerShell to gather information from XMS and NetScaler via REST APIs.
#  This script exports its information to an HTML document for easy viewing (test.hml)
#  - Gatherers Gateway settings and MDX application policy settings. 
#  - Confirms that policy timers are Set to expire in the right order.
#  - Verifies that pushreg listenter access is in background services for WorxMail on iOS
# 
#  Author:  Mike Bowlin
#  Date:  02/12/17
# 
#  Resources used to create script:   
#  - Visual Studio Code for Mac for creation and debugging
#  - URL for overview of using APIs for NetScaler:
#         https://www.citrix.com/blogs/2014/09/19/scripting-automating-netscaler-configurations-using-nitro-rest-api-and-powershell-part-1/
#  - Chrome REST testing client ARC.  Its in the chrome Apps 
#  - On the netscaler, click on Documentation:  download nitro API documentation.  Extract tgz file.  clock on index.html.  Follow your nose
#       NetScaler gateway is referred to as "SSL VPN" in these docs.
#  -    http://docs.citrix.com/en-us/netscaler/11/nitro-api/nitro-rest.html   (note left hand pane of page to get examples)
#  - XenMobile REST API docs
#  -    https://docs.citrix.com/en-us/xenmobile/10-3/xenmobile-rest-api-reference-main.html
param([parameter(Mandatory=$true)][string]$xmsHostname, [parameter(Mandatory=$true)][string]$nsHostname,
        [parameter(Mandatory=$true)][String]$xmsUserName = "administrator", [parameter(Mandatory=$true)][String]$xmsPassword = "password", 
        [parameter(Mandatory=$true)][String]$nsUsername = "nsroot", [parameter(Mandatory=$true)][String]$nsPassword = "nsroot",
        [String]$nsVServer = "_XM_XenMobileGateway")

#Debugging path on host.  if this dir exists, we aren't in the container, so we are debugging. 
#   Change directory below to match your path to the script and netscaler modules
$Global:baseDir = "/Volumes/Macintosh HD/Users/mbbowlin/docker/"
$Global:NSFinctions = ""
if (Test-Path $Global:baseDir) {
    $Global:NSFinctions =  $Global:baseDir +  "NitroConfigurationFunctions"
}
# we are on the container, so export the report to the mount point in the container of the host.
else {
    $Global:baseDir = "/tmp/"
    $Global:NSFinctions = $Global:baseDir +  "NitroConfigurationFunctions"
}
Import-Module $Global:NSFinctions -Force


$xmusername=$xmsUserName
$xmpassword=$xmsPassword
$nsusername=$nsUsername
$nspassword=$nsPassword
$gwName =  $nsVServer  #"_XM_XenMobileGateway"
$Global:sesspolPrefix = "PL_OS_"
$Global:bGwsp  #gateway session policy name found boolean 
$Global:gwspName  #gateway session policy name  
$Global:gwIP = "1.1.1.1"
$Global:hostname=$xmsHostname
$Global:nshostname=$nsHostname
$Global:xmstoken=""
$Global:nstoken=""
$Global:splitDNS = ""
$Global:splitTunnel = ""
$Global:sessionTimeout = ""
$Global:forcedTimeout = ""
$Global:lb="`r`n`r`n"
$Global:scriptUsage = "Arguments: -xmsHostname xms_hostname -nsHostname NetScaler_hostname -xmsUsername xms_admin_user -xmsPassword xms_admin_user_password" + `
                "-nsUsername netscaler_admin_user -nsPassword ns_admin_user_password -nsVServer _XM_XenMobileGateway " + $Global:lb + `
                "NOTE:  -nsVServer is optional.  If left off, the script will default to the name created by the NS GW Wizard."
$DebugPreference = "Continue"


Set-NSMgmtProtocol "http"
$NSSession = Connect-NSAppliance -NSAddress $nsHostname -NSUserName $nsUsername -NSPassword $nsPassword

#Networking IPs
Get-NSIPResource -NSSession $NSSession | Select-Object ipaddress,type,mgmtaccess,state
#Get DNS Settings
#Add-NSDnsNameServer -NSSession $NSSession -DNSServerIPAddress "192.168.0.1" -ErrorAction SilentlyContinue
Write-Host "DNS NAme Servers: " + (Get-NSDnsNameServer -NSSession $NSSession | Select-Object ip, port, type, state, nameserverstate)
$gwTZ =  (Get-NSTimeZone -NSSession $NSSession)
# Get certkeyname for cert bound to vServer so we can query SSL cert info
$gwCertInfoSunject = (Get-NSSSLVServerCertKeyBinding -NSSession $NSSession -VServerName $nsVServer).certkeyname
#Query cert info of certificate bound to the vServer.
$gwCertInfo = (Get-NSSSLCertKey -NSSession $NSSession | Select-Object subject, certkey, cert, key, inform, status, expirymonitor, notificationperiod | Where-Object {($_.certkey -like $gwCertInfoSunject)})  # {($_.certkey -notlike "ns-*")})


#========================================================================================
#Setup auth info for NetScaler connection
$Global:authns = @"
{ 
    "login": 
    { 
        "username":"$nsusername", 
        "password":"$nspassword",
        "timeout":900
    } 
}
"@

#========================================================================================
# Setup auth for XMS Server
$Global:authxms = @"
{ "login" : "$xmusername", "password" : "$xmpassword" }
"@
#$Global:authxms

#========================================================================================
#LineBreak used for breaking up text in output
$lb = "`r`n`r`n"

#========================================================================================
# add spaces in strings at the caps:  Example:
#   ThisIsATest would be converted to This Is A Test
function AddSpacesToSentence([string] $text)
{
    return $text -creplace   '.(?=[^a-z])','$& '

}


#========================================================================================
# Get XMS auth token so we can execute future commands.  

function Get-XMToken(){
    try {
        $stuff = invoke-RestMethod -Uri "https://${hostname}:4443/xenmobile/api/v1/authentication/login" -Method Post -Body $Global:authxms -ContentType "application/json";
    }
    catch {
        Write-Debug "============================================ Error Getting XMS Token ================================================"
        Write-Debug $error[0]
        Write-Debug "====================================================================================================================="
    }

    # Put token in array so powershell will accept it in our invoke-RestMethod calls
    $xmtoken = @{"Auth_Token" = $stuff.auth_token}
    return $xmtoken
}

#========================================================================================
# Get NS auth token so we can execute future commands.  

function Get-NSToken(){
    Write-Debug "Authenticating with NetScaler"

    try {
        #Write-Debug $Global:authns
        $stuff = invoke-RestMethod -Uri "http://${nshostname}/nitro/v1/config/login" -Method Post -Body $Global:authns -ContentType "application/json"
        $cookie = "SESSID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/; sessionid=" + $stuff.sessionid + "; path=/nitro/v1"
        }
    catch {
        Write-Debug "============================================= Error Getting NS Token ================================================"
        Write-Debug $error[0]
        Write-Debug "====================================================================================================================="
    }
    $nstoken = $cookie
    return $nstoken
}

#========================================================================================
# Get XMS default NS Gateway
function Get-DefaultGateway(){
    try {
        $Global:hostname
        $AllXmsGateways = invoke-RestMethod -Method Get  -Uri "https://${hostname}:4443/xenmobile/api/v1/netscaler" -Header $Global:xmstoken  -ContentType "application/json";

        $dg = "https://notFound"
        #Write-Debug  ("Action Name         |URL               |Logon Type  |Default   " )
        foreach ($vip in $AllXmsGateways.agList) {
                #Write-Debug ($vip.name + "  |" + $vip.url + "  |" + $vip.logontype  + "  |" + $vip.default )
                if ($vip.default)
                {
                    $dg = $vip.url
                }
            }

        }
    catch {
        Write-Debug "============================================ Error Getting GW URL from XMS =========================================="
        Write-Debug $error[0]
        Write-Debug "====================================================================================================================="
    }
    $dg
    return $dg
}

#========================================================================================
# Get XMS Application List 
function Get-XmsApplications(){
    $allApps = @()
    try {
        $AllXmsAppIds = invoke-RestMethod -Method Post -Uri "https://${hostname}:4443/xenmobile/api/v1/application/filter" -Header $Global:xmstoken -Body "{}" -ContentType "application/json";

        foreach ($AppId in $AllXmsAppIds.applicationListData.appList) {
                #Write-Debug ($AppId.name + "  |" + $AppId.id + "  |" + $AppId.appType )
                if ($AppId.appType -eq "MDX")
                {
                    #Write-Debug ("MDX App:  " + $AppId.name + "  |" + $AppId.id + "  |" + $AppId.appType ) 
                    $appTemp = Get-XmsApplicationPolicy($AppId.id)
                    $allApps = $allApps + $appTemp
                }
            }

        }
    catch {
        Write-Debug "=====================Error Getting App List Ids from XMS ============================================================"
        Write-Debug $error[0]
        Write-Debug "====================================================================================================================="
    }

    return $allApps
}

#========================================================================================
# Get XMS Application Policy info 
function Get-XmsApplicationPolicy([string] $appId){
    $xmsMdxApp = @()
    try {
        $xmsMdxApp = invoke-RestMethod -Method Get -Uri "https://${hostname}:4443/xenmobile/api/v1/application/mobile/${appId}" -Header $Global:xmstoken -ContentType "application/json";
    }
    catch {
        Write-Debug "=====================Error Getting App Mdx Policy by App Id ========================================================="
        Write-Debug $error[0]
        Write-Debug "====================================================================================================================="
    }

    return $xmsMdxApp.container
}


#========================================================================================
# Get XMS Gateway on NetScaler
function Get-XmNsGatewayFromNS ([string] $ConfiguredGatewayName ) {
    try {
        #$cookie = @{"Cookie"="SESSID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/; sessionid=" + $Global:nstoken + "; path=/nitro/v1"}
        $cookie = @{"Cookie"= "${Global:nstoken}"}
        $AllNetScalerGatewayObj = invoke-RestMethod -Uri "http://${Global:nshostname}/nitro/v1/config/vpnvserver" -Method Get -Headers $cookie -ContentType "application/json";

        #Write-Debug ("Gateway Name         " + "|IP Address  " + "|Port " + "|Session TO"  )
        foreach ($vip in $AllNetScalerGatewayObj.vpnvserver) {
                #Write-Debug  ($vip.name + "  |" + $vip.ipv46 + "  |" + $vip.port + "  |" + $vip.clttimeout  )
                if ($vip.name -eq $ConfiguredGatewayName)
                {
                    $Global:gwIP = $vip.ipv46
                    return $true
                }
            }

        }
    catch {
        Write-Debug "========================== Error Getting Gateways from NetScaler ================================================"  
        Write-Debug  $error[0] 
        Write-Debug "================================================================================================================="
        return $false
    }
    return $false
}

#========================================================================================
# Get XMS Gateway on NetScaler
function Get-XmNsGatewaySessPol ([string] $ConfiguredGatewayName ) {
    try {
        #$cookie = @{"Cookie"="SESSID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/; sessionid=" + $Global:nstoken + "; path=/nitro/v1"}
        $cookie = @{"Cookie"= "${Global:nstoken}"}
        #Write-Debug "http://${Global:nshostname}/nitro/v1/config/vpnvserver_vpnsessionpolicy_binding/${ConfiguredGatewayName}"
        $AllNetScalerSessPol = invoke-RestMethod -Uri "http://${Global:nshostname}/nitro/v1/config/vpnvserver_vpnsessionpolicy_binding/${ConfiguredGatewayName}" -Method Get -Headers $cookie -ContentType "application/json"
        foreach ($sesspol in $AllNetScalerSessPol.vpnvserver_vpnsessionpolicy_binding) {
            #Write-Debug ("Gateway Name         " + "|Pol Name  " + "|Priority "   )
            #Write-Debug ($sesspol.name +" " + $sesspol.policy + " " + $sesspol.priority )
            $sessionFilter = "${Global:sesspolPrefix}${Global:gwIP}"
            if (($sesspol.name -eq $ConfiguredGatewayName) -And  ($sesspol.policy -eq $sessionFilter))      {
                 return $true
            }
        }

    }
    catch {
        Write-Debug "====================================Error Getting Gateways from NetScaler by Name ==============================="   
        Write-Debug  $error[0] 
        Write-Debug "================================================================================================================="
        return $false
    }
    return $false
}

#========================================================================================
# Get NS Gateway Action name for Session policy
function Get-XmNsGatewaySessPolActName ([string] $SessionPolicyName ) {
    try {
        #$cookie = @{"Cookie"="SESSID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/; sessionid=" + $Global:nstoken + "; path=/nitro/v1"}
        $cookie = @{"Cookie"= "${Global:nstoken}"}
        #Write-Debug "http://${Global:nshostname}/nitro/v1/config/vpnsessionpolicy/${SessionPolicyName}"
        $AllNetScalerSessPol = invoke-RestMethod -Uri "http://${Global:nshostname}/nitro/v1/config/vpnsessionpolicy/${SessionPolicyName}" -Method Get -Headers $cookie -ContentType "application/json"
            #Write-Debug ("Sess. Name         " + "|Actioin Name  " + "|Priority "   )
            $sessionFilter = "${Global:sesspolPrefix}${Global:gwIP}"
             foreach ($sesspolaction in $AllNetScalerSessPol.vpnsessionpolicy) {
                 #Write-Debug ($sesspolaction.name +" " + $sesspolaction.action + " " + $sesspolaction.priority )
                if ($sesspolaction.name -eq $SessionPolicyName)      {
                    return $sesspolaction.action
                }
             }
    }
    catch {
        Write-Debug "==================== E R R O R getting Session policy info by pol name ================================"   
        Write-Debug  $error[0] 
        Write-Debug "======================================================================================================="
        return $false
    }
    return $false
}

#========================================================================================
# Get NS Gateway Action parameteres
function Get-XmNsGatewaySessPolActParams ([string] $SessionActionName ) {
    try {
        #$cookie = @{"Cookie"="SESSID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/; sessionid=" + $Global:nstoken + "; path=/nitro/v1"}
        $cookie = @{"Cookie"= "${Global:nstoken}"}
        #Write-Debug "http://${Global:nshostname}/nitro/v1/config/vpnsessionaction"
        $AllNetScalerActionPol = invoke-RestMethod -Uri "http://${Global:nshostname}/nitro/v1/config/vpnsessionaction" -Method Get -Headers $cookie -ContentType "application/json"
            #Write-Debug ("Action Name         " + "|Sess. TO  " + "|Split Tunnel "+ "|Split DNS "+ "|Forced T.O. "+ "|Storefront URL "   )
            #$sessionFilter = "${Global:sesspolPrefix}${Global:gwIP}"
             foreach ($action in $AllNetScalerActionPol.vpnsessionaction) {
                 if ($action.name -eq $SessionActionName){
                    #Write-Debug ($action.name +" " + $action.sesstimeout + " " + $action.splittunnel + " " + $action.splitdns + " " + $action.forcedtimeout+ " " + $action.storefronturl )
                    return $action
                 }
             }
    }
    catch {
        Write-Debug "===========================E R R O R getting session actions ================================================"  
        Write-Debug  $error[0] 
        Write-Debug "============================================================================================================="
        return $false
    }
    return $false
}

#========================================================================================
# Evaluate timers
#   Global netscaler timer variables:
#    $Global:splitDNS 
#    $Global:splitTunnel 
#    $Global:sessionTimeout 
#    $Global:forcedTimeout 
function evalTimers([String] $OS, [String] $appName, [String] $maxOfflinePeriod, [String] $STA, [String] $netowrkAccess, [String] $backgroundServices) {
    $orderedCorrectly = $true
    #Setup display values when null or empry string
    if ($Global:forcedTimeout -eq $null){
        $tmpForceTO = "Off"
        $tmpForceTOVal = 9999999999999999
    }
    else {
        $tmpForceTO = $Global:forcedTimeout/60
        $tmpForceTOVal = [float]$tmpForceTO
    }

    if ($STA -eq ""){
        $tmpSTA = "N/A"
    }
    else {
        $tmpSTA = $STA
    }

    if (  [float]$MaxOfflinePeriod -gt [float]($Global:sessionTimeout/60)) {
        $orderedCorrectly = $false
        $headerString = "<p class=tabred> Warning:  App MaxOfflinePeriod is Greater than NetScaler Session Timeout </p> " 
    }

    if ([float]($Global:sessionTimeout/60) -gt [float]$STA -And $STA -ne "") {
        $orderedCorrectly = $false
        $headerString = $headerString + "<p class=tabred> Warning: NetScaler Session Timeout is greater than Background Service Ticket</p> " 
    }

    if ([float]$STA -gt [float]$tmpForceTOVal -And $STA -ne "") {
        $orderedCorrectly = $false
        $headerString = $headerString + "<p class=tabred> Warning:  App Background Service Ticket is Greater than NetScaler Forced Timeout </p> " 
    }

    if ([float]($Global:sessionTimeout/60) -gt [float]$tmpForceTOVal) {
        $orderedCorrectly = $false
        $headerString = $headerString + "<p class=tabred> Warning:  Session Timeout is Greater than NetScaler Forced Timeout </p> " 
    }

    if ($netowrkAccess -eq "NetworkAccessTunneled" -And (-Not ($backgroundServices  -like "pushreg.xm.citrix.com")) -And $OS -eq "iOS" -And $tmpSTA -ne "N/A") {
        $orderedCorrectly = $false
        $headerString = $headerString + "<p class=tabred> Warning:  SplitTunnel is Off and _ZONE_.pushreg.xm.citrix.com:443 not defined in MDX policy Background network services.  See https://www.citrix.com/blogs/2015/06/11/mobility-experts-a-step-by-step-guide-to-configuring-worxmail-apns/ step 4</p> " 
    }

    $headerString = $headerString + "<p class=tab > Proper Order:  Forced TO >  Background Service Ticket > Session Timeout > Max Offline Period > Inactibity Timer "
    $headerString = $headerString + "<p class=tab>If you have red timer warnings above, please see https://www.citrix.com/blogs/2015/04/08/xenmobile-enterprise-balancing-user-experience-and-security-with-smart-design-decisions/ </p>"
    if ($orderedCorrectly) {
        $headerString = "Session Timers are in proper order"
    }
    #show table of values from NS Gateway and MDX policy settings for this app
    $headerString = $headerString + "<table>"
    $headerString = $headerString + "<tr><td>Forced Timeout</td><td>Background Service Ticket</td><td>Session Timeout</td><td>Max Offline Period</td><td>Inactivity Timer</td></tr>"
    $headerString = $headerString + "<tr><td>" + $tmpForceTO + "</td><td>" + $tmpSTA + "</td><td>" + $Global:sessionTimeout/60 + "</td><td>" + $MaxOfflinePeriod + "</td><td>Need API for XMS</td></tr>"
    $headerString = $headerString + "</tr></table>"
    return $headerString
}

#===========================================================================================================================
# Main code
$Global:xmstoken = Get-XMToken
$Global:nstoken = Get-NSToken

# Get XMS Default Gateway
$defaultGW = Get-DefaultGateway
$defaultGW =  $defaultGW[$defaultGW.Length-1]
Write-Debug  ("NS Gwateway URL configured in XMS server: " + $defaultGW)

# Get Gateway info from NetScaler based on default from XMS server
$XmNsGatewayFromNS = Get-XmNsGatewayFromNS($gwName)

if ($XmNsGatewayFromNS) {
    Write-Debug ("Found XM Gateway on NetScaler: " + $gwName) 
    Write-Debug ("Gathering Session Policy")
}
else {
    # End Exection if we didn't find the Gateway Name Requested (or default created by wizard)
    Write-Debug $Global:scriptUsage
    Write-Error ("Unable to Find XM Gateway on NetScaler: " + $gwName) -Category 'InvalidArgument'
    return 
}

# Get Session Policies based on Gateway Name
$gwsp = Get-XmNsGatewaySessPol($gwName)
$Global:gwspName = "${Global:sesspolPrefix}${Global:gwIP}"
if ($gwsp) {
    Write-Debug ("We found Session policy " + $Global:gwspName)
}
else {
    return
}

# Get Action Name for Session Policy
$sessionPolicyActName = Get-XmNsGatewaySessPolActName($Global:gwspName)
#Write-Debug ("Action Name " + $sessionPolicyActName)

# Get Policy Action to ensure our URL matches XMS server and get parameters/attributes/timers.  Set global vars for later use/comparison
$actionParameters = Get-XmNsGatewaySessPolActParams($sessionPolicyActName)

$Global:splitDNS = $actionParameters.splitdns
$Global:splitTunnel = $actionParameters.splittunnel
$Global:sessionTimeout = $actionParameters.sesstimeout
$Global:forcedTimeout = $actionParameters.forcedtimeout

# Get Applications with MDX policies from XMS server
$allApps = Get-XmsApplications
$preContent2 = ""

foreach ($appName in $allApps)
{
    $preContentTemp = ""
    $finalApp = @()
    $tmpAppListiOS = new-object -TypeName PSObject

    foreach ($mdxPol in $appName.ios.policies){
        $tmpHeader =  $mdxPol.policyName #AddSpacesToSentence($mdxPol.policyName)
        $tmpAppListiOS = $tmpAppListiOS | add-member NoteProperty -Name $tmpHeader -Value $mdxPol.policyValue -PassThru
    }
    $finalApp = $finalApp + $tmpAppListiOS 
    
    $bodyHeader =  "<H2>Application Name: " + $appName.name + " - Platform: iOS "
    #$finalApp[0].MaxOfflinePeriod
    #$finalApp[0].BackgroundServicesExpiration
    $tmpTableInfo = evalTimers "iOS" $appName.name $finalApp[0].MaxOfflinePeriod $finalApp[0].BackgroundServicesExpiration $finalApp[0].NetworkAccess $finalApp[0].BackgroundServices
    $bodyHeader = $bodyHeader + $tmpTableInfo
    $bodyHeader = $bodyHeader + "</p></H2>"
    $preContentTemp = $finalApp | Select-Object * | ConvertTo-Html -PreContent $bodyHeader -Fragment
    $preContent2 = $preContent2 + $preContentTemp

    $preContentTemp = ""
    $finalApp = @()
    $tmpAppListDriod = new-object -TypeName PSObject
    foreach ($mdxPol in $appName.android.policies){
        $tmpHeader = $mdxPol.policyName #AddSpacesToSentence($mdxPol.policyName)
        $tmpAppListDriod = $tmpAppListDriod | add-member NoteProperty -Name $tmpHeader -Value $mdxPol.policyValue -PassThru
    }

    $finalApp = $finalApp + $tmpAppListDriod
    
    $bodyHeader =  "<H2>Application Name: " + $appName.name + " - Platform: Android "
    #$tmpAppListDriod.MaxOfflinePeriod
    #$tmpAppListDriod.BackgroundServicesExpiration
    $tmpTableInfo = evalTimers "Android" $appName.name $tmpAppListDriod.MaxOfflinePeriod $tmpAppListDriod.BackgroundServicesExpiration $finalApp[0].NetworkAccess $finalApp[0].BackgroundServices
    $bodyHeader = $bodyHeader + $tmpTableInfo
    $bodyHeader = $bodyHeader + "</p></H2>"

    $preContentTemp = $finalApp | Select-Object * | ConvertTo-Html -PreContent $bodyHeader -Fragment
    $preContent2 = $preContent2 + $preContentTemp

}


#Confirm that URL matches XMS server gateway URL
#    - Parse action parameters.storefronturl:  storefronturl from NetScaler : https://xms.bowlins.com:8443
#    - Split based on // to get the hostname:port
$sfURLparsed = $actionParameters.storefronturl.split("//")
#    - length-1 should give us the hostname:port
#    - So split this to seperate the hostname out.  
$sfURLparsed = $sfURLparsed[$sfURLparsed.length-1].split(":")
#    - We should now have array with [0] being hostname (-2) and port being 1 (-1)
#$sfURLparsed[$sfURLparsed.length-2]

if ($Global:hostname -notmatch $sfURLparsed[$sfURLparsed.length-2]){
    Write-Debug "Gateway XMS storefront URL / XMS server and xms-hostname do not match between "
}

#-------------------------------------
#  Need to get common name from cert / gateway to ensure SSL cert / hostname is valid.
#-------------------------------------


$a = "<style>"
$a = $a + "BODY{background-color:peachpuff;}"
$a = $a + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;margin-left: 40px; }"
$a = $a + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:thistle}"
$a = $a + "TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:palegoldenrod}"
$a = $a + "p{font-size: 50%}"
$a = $a + ".colorit: {color: red; }"
$a = $a + ".odd  { background-color:#ffffff; }"
$a = $a + ".even { background-color:#dddddd; }"
$a = $a + ".tab  { margin-left: 40px; }"
$a = $a + ".tabred { margin-left: 40px;color: red; }"
$a = $a + "</style>"

$bodyHeader = "<H2>Gateway Settings for vServer: " + $gwName + "</H2>" 
$bodyHeaderCert = "<H2>Gateway Certificat Information for vServer: " + $gwName + "<p class=tab>NetScaler Timezone:     " + $gwTZ +  "</p><p class=tab>Default Gateway URL from XMS Server:  " + $defaultGW + "</H2>" 

$newName = @{name="Action Name";expression={$_.name}}
$sDNS = @{name="Split DNS";expression={$_.splitdns}}
$sTun = @{name="Split Tunnel";expression={$_.splittunnel}}
$sTO = @{name="Session Timeout";expression={$_.sesstimeout}}
$sFTO = @{name="Forced Timeout";expression={$_.forcedtimeout}}
$sfUrl = @{name="Storefront URL";expression={$_.storefronturl}}
$getDate = Get-Date
$currentTime = @{name="Current Time";expression={$getDate}}

#$preContent = $actionParameters | Select-Object $newName, $sDNS, $sTun, $sTO, $sFTO, $sfUrl, $currentTime | ConvertTo-HTML -head $a -body $bodyHeader | Out-String
# Out-File "/Volumes/Macintosh HD/Users/mbbowlin/docker/test.htm"

$preContent0 = $gwCertInfo | ConvertTo-Html -PreContent $bodyHeaderCert -Fragment 

$preContent1 = $actionParameters | Select-Object $newName, $sDNS, $sTun, $sTO, $sFTO, $sfUrl, $currentTime | ConvertTo-Html -PreContent $bodyHeader -Fragment 

#$preContent1

# Add all HTML to final doc
$preContent1 = $preContent1 + $preContent0 + $preContent2

$htmlDocument = ConvertTo-Html -Head $a -PreContent $preContent1| Out-String
#$htmlDocument -replace '<table>\r?\n</table>' | Out-File "/Volumes/Macintosh HD/Users/mbbowlin/docker/test.htm"
# if we are on my mac 
$reportName = $Global:baseDir + "test.htm"
$htmlDocument | Out-File $reportName 
#$htmlDocument | Out-File "/tmp/test.htm"


