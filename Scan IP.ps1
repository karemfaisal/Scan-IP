function Scan-IP{
<#

.SYNOPSIS

This script will help users for scanning IPs in various IP-check vendors
1- Virustotal
2- OTX
3- Talos Blacklist
4- DNS checker  -- 53 Black Lists
5- AbuseIPDB


Function: Scan IP
Author: Karem Ali
Required Dependencies: APIs keys, Powershell V3 or higher, Install PSWriteColor Module
Version: 1.0

.DESCRIPTION

Helpful functions for Scanning IPs

.PARAMETER APIs

Mandatory: it's the path for the APIs file, it is Mandatory to able to talk with Service providers

.PARAMETER IPs

Mandatory: The IPs that script will check

.PARAMETER malout

Optional: Now there are 5 services the script checks the IPs in, if you set malout to be 2 then the script will create a file contains the IPs that appears to be Malicious in 2 or more of the 5

.PARAMETER cleanout

Optional: Now there are 5 services the script checks the IPs in, if you set malout to be 2 then the script will create a file contains the IPs that appears to be Good in 2 or more of the 5

.PARAMETER v

Switch: Verbose output

	
.EXAMPLE

Scan-IP -APIs APIs.txt -IPs 77.247.110.222,111.221.29.254 

.EXAMPLE

Scan-IP -APIs APIs.txt -IPs (get-content -path IPs.txt) 

.EXAMPLE

Scan-IP -APIs APIs.txt -IPs (get-content -path IPs.txt) -malout 2 -v

.NOTES
Install-Module -Name PSWriteColor "Run by Admin" for write-color

You have to set execution policy in powershell to bypass


#>

 [CmdletBinding()]
    Param(
        [string[]] $IPs,
        [string[]] $APIs,
        [switch]$V,
        [int]$malout, 
        [int]$cleanout 

    )

process{
    if(!$APIs)
    {

        Write-Color -Text "You have to supply APIs argument, which is the path for the APIs file" -Color Red

    }
   

    
    else
    {
    $API = Get-Content -Path $APIs
    $VT_API = $API[0].Split(":")[1]  -split ","
    $Abuse_API = $API[1].Split(":")[1]  -split ","
    $OTX_API = $API[2].Split(":")[1]  -split ","
    if($IPs)
    {
        #Maximum 15 Request in Minut
        $talos_blacklist = (Invoke-RestMethod "https://talosintelligence.com/documents/ip-blacklist").split("`n")
        $VT_Res = New-Object System.Collections.Generic.List[object]
        $i = 0;
        $j = 0;
        $Sleep = [System.Math]::Ceiling( 60 / ($VT_API.Length * 4))
        foreach($IP in $IPs)
        {
            Write-Host -ForegroundColor Green "`n`n$IP Scan Result: `n--------------------------"
            if($VT_API)
            {
                $Index_of_APIKey = ([system.math]::Floor($i / 4)) % $VT_API.Length
                $API = $VT_API[$Index_of_APIKey]
                $gvx = Invoke-RestMethod -Uri "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=$API&ip=$ip" -Method GET
                $VT_Res.Add($gvx)
                if([string]::IsNullOrEmpty($gvx.detected_urls) -and [string]::IsNullOrEmpty($gvx.detected_communicating_samples) -and [string]::IsNullOrEmpty($gvx.detected_referrer_samples) -and [string]::IsNullOrEmpty($gvx.detected_downloaded_samples))
                {
                    Write-Color -Text "`n`n Virus total Result :" ,"    Clean`n`n" -Color Green,White
                    if($cleanout)
                    {
                        $IP | Out-File -Append tempGoodIPs.txt

                    }
                }
                else
                {

                    Write-Color -Text "Viruse total Result :" ,"    Has Malicious behaviour" -Color Green,White
                    if($v)
                    {
                        Write-Color -Text "`n `n Detected URLs" -Color Green
                        $gvx.detected_urls  | Format-Table -AutoSize
                        Write-Color -Text "`n `n Detected downloaded samples" -Color Green
                        $gvx.detected_downloaded_samples | Format-Table -AutoSize
                        Write-Color -Text "`n `n Detected referrer samples" -Color Green
                        $gvx.detected_referrer_samples | Format-Table -AutoSize
                        Write-Color -Text "`n `n Detected communicating samples" -Color Green
                        $gvx.detected_communicating_samples | Format-Table -AutoSize
                    }
                    if($malout)
                    {
                        $IP | Out-File -Append tempMalIPs.txt

                    }

                }

                Start-Sleep -Seconds $Sleep
            }


            if($Abuse_API)
            {
                
                $ty = ((Invoke-WebRequest "https://api.abuseipdb.com/api/v2/check" -Method Get -Body @{'ipAddress' = "$IP" ; 'maxAgeInDays'='90' ; 'verbose'='' } -Headers @{'key' = "$Abuse_API" ; 'Accept' = 'application/json'}).content | ConvertFrom-Json).data

                if($ty.abuseConfidenceScore -gt 0)
                {

                    Write-Color -Text "AbuseIpDB Result : " ,"  Has Malicious behaviour", "   abuseConfidenceScore is:  ", $ty.abuseConfidenceScore -Color Green,White,Green,White
                    if($v)
                    {
                            Write-Color -Text "`n `n abuseConfidenceScore:  " , $ty.abuseConfidenceScore -Color Green,White
                            Write-Color -Text "`n `n totalReports:  ", $ty.totalReports -Color Green,White
                            Write-Color -Text "`n `n countryNam:  " , $ty.countryName -Color Green,White
                            

                    }
                    if($malout)
                    {
                        $IP | Out-File -Append tempMalIPs.txt

                    }
                }
                else
                {
                    Write-Color -Text "`n`nAbuseIpDB Result : " ,"  Clean" -Color Green,White
                    if($cleanout)
                    {
                        $IP | Out-File -Append tempGoodIPs.txt

                    }

                }

            }


            if($OTX_API)
            {
                 $uu = Invoke-RestMethod https://otx.alienvault.com/api/v1/indicator/IPv4/$IP  -Headers @{'X-OTX-API-KEY'= "$OTX_API"} -Method Get
                if( $uu.pulse_info.pulses.Count -gt 1)
                {
                    Write-Color -Text "`n`nOTX Result : " ,"  Has Malicious behaviour" -Color Green,White
                    if($v)
                    {
                        $uu.pulse_info.pulses | Select-Object name,description,created,modified | Format-Table -AutoSize
                    }
                    if($malout)
                    {
                        $IP | Out-File -Append tempMalIPs.txt

                    }
                }
                else
                {

                 Write-Color -Text "`n`nOTX Result : " ,"  Clean" -Color Green,White
                 if($cleanout)
                  {
                        $IP | Out-File -Append tempGoodIPs.txt

                  }

                }


            }

        
            if($talos_blacklist -match $IP)
            {
                Write-Color -Text "`n`nTalos Black List Result : " ,"  Black listed" -Color Green,White
                 if($malout)
                 {
                    $IP | Out-File -Append tempMalIPs.txt

                 }

            }
            else
            {
                Write-Color -Text "`n`nTalos Black List Result : " ,"  Clean" -Color Green,White
                if($cleanout)
                 {
                        $IP | Out-File -Append tempGoodIPs.txt

                 }

            }


            $ghb = Invoke-RestMethod "https://dnschecker.org/ajax_files/ip_blacklist_checker.php" -Method Post -Body @{'host' = "$IP"}
            if(($ghb.result.dnsBL | where{$_.found -match "true"}).url.count -ge 4)
            {
                Write-Color -Text "`n`nDNS Checker Black List Result : " ,"  Black listed" -Color Green,White
                if($v)
                {
                    ($ghb.result.dnsBL | where{$_.found -match "true"})

                }
                if($malout)
                 {
                    $IP | Out-File -Append tempMalIPs.txt

                 }

            }
            else
            {
                Write-Color -Text "`n`nDNS Checker Black List Result : " ,"  Clean" -Color Green,White
                if($cleanout)
                 {
                            $IP | Out-File -Append tempGoodIPs.txt

                 }
            }



        }

   

    }

    }

    if((Test-Path("tempMalIPs.txt")))
    {

        Get-Content -Path tempMalIPs.txt | group | where {$_.count -gt $malout} | Select-Object -ExpandProperty Name | Out-File  MalIPs.txt
        Remove-Item -Path tempMalIPs.txt

    }

    if((Test-Path("tempGoodIPs.txt")))
    {

        Get-Content -Path tempGoodIPs.txt | group | where {$_.count -gt $cleanout} | Select-Object -ExpandProperty Name | Out-File  GoodIPs.txt
        Remove-Item -Path tempGoodIPs.txt

    }

    
}




}