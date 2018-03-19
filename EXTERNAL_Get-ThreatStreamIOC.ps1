<#
.SYNOPSIS
    Retrieves hashes (MD5, SHA1, and SHA256) from ThreatStream's API. Saves the hashes in an Open IOC format (.ioc) in a local folder which Tanium monitors.

.DESCRIPTION
    ### Cyber Security Analytics - Detection Analysis Response Team ###
    Date Updated:  28-DEC-2017
    Revision History 1.1: Corrected parsing of hashes, was missing MD5 due to length. Corrected XML format.
    Revision History 1.0: Added CyberArk support, changed script to run from the scripting server. 
    Version: 1.1
    Author: Colin Nichols


.OUTPUTS
    <Drive:>\dart\<filename>.ioc
.NOTES
    Runs from the DART Scripting Server (va10p50879.us.ad.wellpoint.com) via scheduled task.
    Format of file must be in UTF8. Other file formats will not be recognized by Tanium.
    ThreatStream API limits results to 1000 total.
    Tanium Client only supports MD5, SHA1 ,and SHA256 hashes, so in the json call we check that the value length is one of those and then use a switch to create each entry.
#>
Try {
    $CyberPass = New-Object -ComObject "COMPasswordSDK.PasswordSDK"
    $CyberPassReq = New-Object -ComObject "COMPasswordSDK.PSDKPasswordRequest"
    $CyberPassReq.Safe = "SVC-CSA_Automation"
    $CyberPassReq.UserName = "dl-dartengineering@anthem.com"
    $CyberPassReq.AppID = "CSA_Prod"
    $CyberPassReq.Reason = "Get-ThreatStreamIOC.ps1"
}
Catch {
    Send-MailMessage -To $strEmailTo -SmtpServer smtp.wellpoint.com -From noreply@anthem.com -Subject "[ThreatStream IOC] - FAILURE - Unable to Obtain IOC feed for Tanium on $env:COMPUTERNAME" -Body "Failed to load CyberArk Credentials."
    Break
}
## URL of ThreatStream Intelligence API
$strAPIURL = "https://api.threatstream.com/api/v2/intelligence/"
#blacklist of hashes to not process
$excludeHashes = Get-Content -Path "$pwd\inputfiles\Get-ThreatStreamIOC_blacklist.txt"
## Override ThreatStream default result limit of 20 (however, a hard limit of 1000 is still imposed)
$intResultLimit = 0
## Set minimum confidence score
$intConfidence = 80
## How many days back?
$intDaysBack = -1 #Go back to Yesterday
## What type of indicator (iType)
$strTSIType = "mal_md5"
$strEmailTo = "Colin.Nichols@anthem.com", "Kelsey.Prior@anthem.com"
[System.Net.ServicePointManager]::SecurityProtocol += "Tls12"
[System.Net.ServicePointManager]::SecurityProtocol += "Tls11" #added both Tls versions for better web connectivity.
## format date/time stamp to match ThreatStream standards
$strDate = Get-Date -Format s
$strModifiedTS = Get-Date -Format s -Date (Get-Date).AddDays($intDaysBack).ToUniversalTime()

## create hashtable of desired (some required) attributes
$hshParams = @{username = $($CyberPass.GetPassword($CyberPassReq).username); api_key = $($CyberPass.GetPassword($CyberPassReq).content); limit = $intResultLimit; confidence__gte = $intConfidence; modified_ts__gte = $strModifiedTS; itype = $strTSIType}

## make API request and store JSON responses, if it fails send us an email.
try {
    Get-Content "\\us.ad.wellpoint.com\netlogon\Enterprise Remote Drive Mapping.cmd" | Out-Null #Do this so that if there are disconnected sessions the service account establishes a connectionw with the proxy
    Start-Sleep -Seconds 20    
    $jsonResponse = Invoke-RestMethod -Uri $strAPIURL -Body $hshParams -ErrorVariable jsonErr | Select-Object -ExpandProperty objects | Select-Object -ExpandProperty value | Where-Object {$_.length -eq "32" -or $_.length -eq "40" -or $_.length -eq "64"}
}
catch {
    Send-MailMessage -To $strEmailTo -SmtpServer smtp.wellpoint.com -From noreply@anthem.com -Subject "[ThreatStream IOC] - FAILURE - Unable to Obtain IOC feed for Tanium on $env:COMPUTERNAME" -Body "Check the Powershell Script and re-run the task. $jsonErr"
    Exit
}
function New-Indicator {
    <#
    .SYNOPSIS
    function will genearte the indicator for export to xml
    
    .PARAMETER strHash
    Uses the hash which was obtained for the REST call to ThreatStream
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(ValueFromPipeline)][string]$strHash
    )

    if ($excludeHashes -notcontains $strHash) {
        #test if the hash we found is in the blacklist. If it is, skip it.
        switch ($strHash.length) {
            32 {
                # "MD5" 
@"
           <IndicatorItem id="$(([System.Guid]::NewGuid()).GUID)" condition="IS">
                <Context document="FileItem" type="mir" search="FileItem/Md5sum"/>
                <Content type="md5">$strHash</Content>
            </IndicatorItem>

"@        
            }
            40 {
                # "SHA1"
@"
           <IndicatorItem id="$(([System.Guid]::NewGuid()).GUID)" condition="IS">
                <Context document="FileItem" type="mir" search="FileItem/Sha1sum"/>
                <Content type="string">$strHash</Content>
            </IndicatorItem>

"@        
            }
            64 {
                # "SHA256"
@"
           <IndicatorItem id="$(([System.Guid]::NewGuid()).GUID)" condition="IS">
                <Context document="FileItem" type="mir" search="FileItem/Sha256sum"/>
                <Content type="string">$strHash</Content>
            </IndicatorItem>

"@    
            }
            #default {}
        }
    }
}

# Create file
If ($jsonResponse.count -gt 0) {
    $xmlContents = 
@"
<?xml version="1.0"?>
<ioc id="$(([System.Guid]::NewGuid()).GUID)" last-modified="$strDate" xmlns="http://schemas.mandiant.com/2010/ioc" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.mandiant.com/2010/ioc/ioc.xsd http://schemas.mandiant.com/2010/ioc/TR/ioc-TR.xsd">
    <short_description>ThreatStream IOC Export at $strDate</short_description>
    <description>PowerShell ThreatStream IOC Export at $strDate</description>
    <authored_by>ThreatStream</authored_by>
    <authored_date>$strDate</authored_date>
    <definition>
        <Indicator id="$(([System.Guid]::NewGuid()).GUID)" operator="OR">   

"@
    $xmlContents += $jsonResponse | ForEach-Object {New-Indicator $_}
    $xmlContents +=
@"
        </Indicator>
    </definition>
</ioc>
"@

    #Write to IOC Monitored folder.
    Try {
        $xmlContents | Out-File \\va10p51472\dart\ioc\$($strDate.Replace(":",".")).ioc -Encoding utf8 #Send to Dev
        $xmlContents | Out-File \\va10pwvtan300\dart\ioc\$($strDate.Replace(":",".")).ioc -Encoding utf8 #Send to Prod
        Send-MailMessage -To $strEmailTo -SmtpServer smtp.wellpoint.com -From noreply@anthem.com -Subject "[ThreatStream IOC] - SUCCESS - IOC feed for Tanium on $env:COMPUTERNAME" -Body "IOCs Imported $($jsonResponse.count):`n$($jsonResponse | ForEach-Object {"$_`n"})`nGo about your biz."
    }
    Catch {
        Send-MailMessage -To $strEmailTo -SmtpServer smtp.wellpoint.com -From noreply@anthem.com -Subject "[ThreatStream IOC] - FAILED - IOC feed for Tanium on $env:COMPUTERNAME" -Body "Something went wrong writing the IOCs to ze servers."
    }
}

If ($jsonResponse.count -eq 0) {
    Send-MailMessage -To $strEmailTo -SmtpServer smtp.wellpoint.com -From noreply@anthem.com -Subject "[ThreatStream IOC] - SUCCESS - IOC feed for Tanium on $env:COMPUTERNAME" -Body "No IOCs met our criteria for this run."
}

#Cleanup files older than 90 Days 

#Try {
#    Get-ChildItem -Path "\\va10p51472\dart\ioc\","\\va10pwvtan300\dart\ioc\" -Recurse -File | Where-Object CreationTime -lt (Get-Date).AddDays(-90)  | Remove-Item
#    }
#catch {}
