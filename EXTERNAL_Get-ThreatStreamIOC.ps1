<#
.SYNOPSIS
    Retrieves hashes (MD5, SHA1, and SHA256) from ThreatStream's API. Saves the hashes in an Open IOC format (.ioc) in a local folder which Tanium monitors.

.DESCRIPTION
    ### Cyber Security Analytics - Detection Analysis Response Team ###
    Date Updated:  29-DEC-2017
    Revision History: Sanitized for external release
    Author: Colin Nichols
    Version: 1.0

.OUTPUTS
    <Drive:>\dart\<filename>.ioc

.NOTES
    Format of file must be in UTF8. Other file formats will not be recognized by Tanium.
    ThreatStream API limits results to 1000 total.
    Tanium Client only supports MD5, SHA1, and SHA256 hashes. In the json call we check that the value length is one of those and then use a switch to create each entry.
#>

## URL of ThreatStream Intelligence API
$strAPIURL = "https://api.threatstream.com/api/v2/intelligence/"
## Override ThreatStream default result limit of 20 (however, a hard limit of 1000 is still imposed)
$intResultLimit = 0
## Set minimum confidence score
$intConfidence = 80
## How many days back?
$intDaysBack = -1 #Go back to Yesterday
## What type of indicator (iType)
$strTSIType = "mal_md5"
$strEmailTo = <#Alert email Recipents#>

## format date/time stamp to match ThreatStream standards
$strDate = Get-Date -Format s
$strModifiedTS = Get-Date -Format s -Date (Get-Date).AddDays($intDaysBack).ToUniversalTime()

## create hashtable of desired (some required) attributes
$hshParams = @{username = <#USERNAME#>""; api_key = <#API KEY#>""; limit = $intResultLimit; confidence__gte = $intConfidence; modified_ts__gte = $strModifiedTS; itype = $strTSIType}

## make API request and store JSON responses, if it fails send us an email.
try {
    $jsonResponse = Invoke-RestMethod -Uri $strAPIURL -Body $hshParams  | Select-Object -ExpandProperty objects | Select-Object -ExpandProperty value | Where-Object {$_.length -eq "40" -or $_.length -eq "64" -or $_.length -eq "128"}
}
catch {
    #Send-MailMessage -To $strEmailTo -SmtpServer <#SMTP Location#> -From <#REPLY ADDRESS#> -Subject "[ThreatStream IOC] - FAILURE - Unable to Obtain IOC feed for Tanium on $env:COMPUTERNAME" -Body "Check server's abililty to contact ThreatStream and re-run the task."
    #Exit
}
function New-Indicator {
    <#
    .SYNOPSIS
    Genearte the indicator for export to xml
    
    .PARAMETER strHash
    Uses the hash which was obtained for the REST call to ThreatStream
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(ValueFromPipeline)][string]$strHash
    )

    #Switch for MD5, SHA1, & SHA256
    switch ($strHash.length) {
        32 { # "MD5" 
@"
           <IndicatorItem id="$(([System.Guid]::NewGuid()).GUID)" condition="is">
                <Context document="FileItem" type="mir" search="FileItem/Md5sum"/>
                <Content type="md5">$strHash</Content>
            </IndicatorItem>

"@        
        }
        40 { # "SHA1"
@"
           <IndicatorItem id="$(([System.Guid]::NewGuid()).GUID)" condition="is">
                <Context document="FileItem" type="mir" search="FileItem/Sha1sum"/>
                <Content type="string">$strHash</Content>
            </IndicatorItem>

"@        
        }
        64 { # "SHA256"
@"
           <IndicatorItem id="$(([System.Guid]::NewGuid()).GUID)" condition="is">
                <Context document="FileItem" type="mir" search="FileItem/Sha256sum"/>
                <Content type="string">$strHash</Content>
            </IndicatorItem>

"@    
        }
        #default {} #No default case, can add more if desired
    }
}

# Create file
If ($jsonResponse.count -gt 0) {
$xmlContents = 
@"
<?xml version="1.0"?>
<ioc id="$(([System.Guid]::NewGuid()).GUID)" last-modified="$strDate" xmlns="http://schemas.mandiant.com/2010/ioc" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.mandiant.com/2010/ioc ioc.xsd http://schemas.mandiant.com/2010/ioc/TR/ ioc-TR.xsd">>
    <short_description>ThreatStream IOC Export at $strDate</short_description>
    <description>PowerShell ThreatStream IOC Export at $strDate</description>
    <authored_by>ThreatStream</authored_by>
    <authored_date>$strDate</authored_date>
    <definition>
        <Indicator id="$(([System.Guid]::NewGuid()).GUID)" operator="or">   

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
        $xmlContents | Out-File <#path to IOC location#>\$($strDate.Replace(":",".")).ioc -Encoding utf8 #Send to Dev
        #Send-MailMessage -To $strEmailTo -SmtpServer <#SMTP Location#> -From <#REPLY ADDRESS#> -Subject "[ThreatStream IOC] - SUCCESS - IOC feed for Tanium on $env:COMPUTERNAME" -Body "IOCs Imported: $($jsonResponse.count)."
    }
    Catch {
        #Send-MailMessage -To $strEmailTo -SmtpServer <#SMTP Location#> -From <#REPLY ADDRESS#> -Subject "[ThreatStream IOC] - FAILED - IOC feed for Tanium on $env:COMPUTERNAME" -Body "Something went wrong writing the IOCs to destination servers."
    }
}