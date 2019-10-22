## Scan IP

This PowerShell script aims to automate the process of scanning IPs in SOC (Security Operation Center)

it searches the IPs in many Vendors

- Virus Total

- Abuse IP DB

- OTX

- DNS checker -- 53 Black Lists

- Talos Black list

  

**Dependencies**

-  Install PSWriteColor Module

  ```powershell
  Install-Module -Name PSWriteColor
  ```

- PowerShell v3 or Higher

- Import the Script as Module

  ```powershell
  Import-module Scan-IP.ps1
  ```

  

**Usage**

*use help to know every thing about the script*

```powershell
get-help Scan-IP -Detailed
```



**Examples**

```por
Scan-IP -APIs APIs.txt -IPs 77.247.110.222,111.221.29.254 
```

```powershell
Scan-IP -APIs APIs.txt -IPs (get-content -path IPs.txt)
```

```powershell
Scan-IP -APIs APIs.txt -IPs (get-content -path IPs.txt) -malout 2 -v
```

**APIs file**

```ini
[VirusTotal]:API1,API2,API3
[AbuseDB]:API
[OTX]:API
```

for virus total, you can only use 4 queries in the minute, if you want to speed the scanning, provide more than 1 API, and the script will run 4 * n quires' in the minute



![outpu1](https://raw.githubusercontent.com/karemfaisal/Scan-IP/master/Misc/output1.JPG)



### Authors

* **Karem Ali**  - [twitter](https://twitter.com/KaremAliFaisal) [LinkedIn](https://www.linkedin.com/in/karem-ali-14a14910b/l)



### To-Do

- HoneyDB -- the free quota is 1500 query every month
- ipvoid -- the free quota is 250 query for one month
- Scan Domains





