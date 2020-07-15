#Invoke-BorgKit
#2020 tanktopsecurity.com // tanktopLogger
#https://github.com/tanktopSecurity
#References where I used another person's script or code are above each code block
#Items marked with "Task - " will be on the readme.md page

function Invoke-BorgKit () {

    param(
     [Parameter(Mandatory = $true)]
     [AllowEmptyString()]
     [string]$DomainName,
     [Parameter(Mandatory = $true)]
     [AllowEmptyString()]
     [Security.SecureString]$DSRMpassword,
     [Parameter()]
     [string]$version
 )
 
    #https://serverfault.com/questions/406933/powershell-parameters
    Write-Host "Running BorgKit..."
    Write-Host "  We are the Borg. Lower your shields and surrender your ships." -ForegroundColor DarkGray
    Write-Host "  We will add your biological and technological distinctiveness to our own." -ForegroundColor DarkGray
    Write-Host "  Your culture will adapt to service us. Resistance is futile." -ForegroundColor DarkGray
    Start-Sleep -Seconds 10

    $theEnd = "I am the beginning, the end, the one who is many. I am the Borg."
    $disparity = "You imply disparity, where none exists"
    $chaos = "I bring order to chaos"

    function Create-BorgKitFolders {
    
        $borgKitFolders = "C:\BorgKit","C:\BorgKit\Downloads\MSFT\ADMX","C:\BorgKit\Downloads\Scripts","C:\BorgKit\Downloads\MSFT\SecBaseLines","C:\BorgKit\Downloads\MSFT\Tools", `
                    "C:\BorgKit\SecBaseLines\MSFT","C:\BorgKit\SecBaseLines\GOOG","C:\BorgKit\ADMX\MSFT ","C:\BorgKit\Installers\GOOG","C:\BorgKit\Scripts\PAW",`
                    "C:\BorgKit\SchTasks\Installers","C:\BorgKit\Tools"
    
        Write-Host "Creating BorgKit Folder Structure..."
    
        foreach ($folder in $borgKitFolders) {
    
            if (!(Test-Path -Path $folder)) {
                New-Item -Path $folder -ItemType Directory | Out-Null
                Write-Host "  Creating $folder"
                Write-Host "    Complete" -ForegroundColor Green
            }
            else {
                Write-Host "  Folder $folder already exists" -ForegroundColor Yellow
                Write-Host "    Continuing" -ForegroundColor Green
    
            }
        }
    }
    
    function Download-BorgCube {
        #add version variable
        $borgCube = "https://raw.githubusercontent.com/tanktopArmy/BorgKit/master/1909.csv"
        $borgCubecsv = "C:\borgKit\Scripts\borgCube.csv"
    
        if (!(Test-Path -Path $borgCubecsv)) {
    
            Write-Host "Downloading URL Manifest..."
            Invoke-WebRequest -Uri $borgCube -OutFile $borgCubecsv
            $script:csv = Import-Csv $borgCubecsv
            Write-Host "    Complete" -ForegroundColor Green
            Write-Host ""
        }
    }
    
    function Check-Bookmark {
        Write-host "Checking for previous invocation..."
        Start-Sleep -Seconds 5
        $script:bookmark = Get-Item C:\BorgKit\Scripts\locutus.txt -ErrorAction SilentlyContinue
    
        if ($bookmark) {
            $script:status = "continue"
            Write-Host "  Previous invocation detected" -ForegroundColor Yellow
            Write-Host "  We will proceed to earth, and if you intervene, we will destroy you" -ForegroundColor DarkGray
            Write-Host "    Continuing" -ForegroundColor Green
            Write-Host
            Start-Sleep -Seconds 5
        }
        else {
            $script:status = "new"
            Write-Host "  No previous invocation detected" -ForegroundColor Yellow
            Write-Host "    Continuing" -ForegroundColor Green
            Write-Host
            Start-Sleep -Seconds 5
        }
    }
    
    function RSAT-Prereqs {
        Write-Host "Checking Tool Prereqs..."

        $BitlockerTools = Get-WindowsFeature -Name RSAT-Feature-Tools-BitLocker-BdeAducExt | Select-Object -ExpandProperty InstallState
        if ($BitlockerTools -ne "Installed") {
            Write-Host "  Installing Bitlocker Tools"
            Install-WindowsFeature -Name RSAT-Feature-Tools-BitLocker-BdeAducExt | Out-Null
            Write-Host "    Complete" -Foregroundcolor Green
            Write-Host
        }
    
        $ADTools = Get-WindowsFeature -Name RSAT-AD-Tools | Select-Object -ExpandProperty InstallState
        if ($ADTools -ne "Installed") {
            Write-Host "  Installing AD Tools"
            Install-WindowsFeature -Name RSAT-AD-Tools | Out-Null
            Write-Host "    Complete" -Foregroundcolor Green
            Write-Host
        }
    
        $DNSTools = Get-WindowsFeature -Name RSAT-DNS-Server | Select-Object -ExpandProperty InstallState
        if ($DNSTools -ne "Installed") {
            Write-Host "  Installing DNS Tools"
            Install-WindowsFeature -Name RSAT-DNS-Server | Out-Null
            Write-Host "    Complete" -ForegroundColor Green
            Write-Host
        }
    }
    
    function Domain-PreReqs {
        Write-Host "Checking Domain Prereqs..."
        $ErrorActionPreference = "SilentlyContinue"
        $script:forest = Get-ADDomain | Select-Object -ExpandProperty Forest
        if ($forest) {
            $script:status = "continue"
            Write-Host "AD Forest $forest detected"
            Write-Host "    Continuing" -ForegroundColor Green
            Write-Host
            $ErrorActionPreference = "Continue"
        }
    
        if (!($forest)) {
            Write-Host "  Installing AD Domain Services Feature and Tools"
            Install-WindowsFeature -Name AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools | Out-Null
            Write-Host "    Complete" -ForegroundColor Green
            Write-Host
            Write-Host "  Installing Forest and Domain"
    
            Import-Module ADDSDeployment | Out-Null
            Install-ADDSForest `
                -DomainName $domainName `
                -SafeModeAdministratorPassword $DSRMpassword `
                -CreateDnsDelegation:$false `
                -DatabasePath "C:\Windows\NTDS" `
                -DomainMode "WinThreshold" `
                -ForestMode "WinThreshold" `
                -InstallDns:$true `
                -LogPath "C:\Windows\NTDS" `
                -NoRebootOnCompletion:$true `
                -SysvolPath "C:\Windows\SYSVOL" `
                -Force:$true
            #Set Bookmark for next run
            New-Item C:\BorgKit\Scripts\locutus.txt | Out-Null
            Write-Host "    Forest install completed." -ForegroundColor Green
            Write-Host "      Rebooting in 30 seconds" -ForegroundColor Yellow
            Write-Host
            #https://www.powershellgallery.com/packages/WindowsImageConverter/1.0/Content/Set-RunOnce.ps1
            $script = "%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\BorgKit\Scripts\Invoke-BorgKit.ps1 -DomainName a -DSRMpassword b"
            New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name '!ContinueBorgKit' -Value $script -PropertyType ExpandString
            Start-Sleep -Seconds 30
            Restart-Computer -Force
        }
    }
    
    function Create-PolicyFolders {
    
        $ErrorActionPreference = 'SilentlyContinue'
        $SYSVOLpath = Get-Item -Path "\\$forest\SYSVOL\$forest\policies\PolicyDefinitions"
    
        if (!($SYSVOLpath)) {
            Write-Host "Creating Central Policy Definitiions folders..."
            New-Item -Path \\$forest\SYSVOL\$forest\policies\PolicyDefinitions -ItemType Directory | Out-Null
            New-Item -Path \\$forest\SYSVOL\$forest\policies\PolicyDefinitions\$language\ -ItemType Directory | Out-Null
            New-Item -Path \\$forest\SYSVOL\Software -ItemType Directory | Out-Null
            Write-Host "  Complete" -ForegroundColor Green
            Write-Host
        }
        else {
            Write-Host "  Folder already exists...not creating"
            Write-Host
        }
    
        $ErrorActionPreference = 'Continue'
    }
    
    function Download-Files {
        #https://stackoverflow.com/questions/41618766/powershell-invoke-webrequest-fails-with-ssl-tls-secure-channel
        [Net.ServicePointManager]::SecurityProtocol = 
            [Net.SecurityProtocolType]::Tls12 -bor `
            [Net.SecurityProtocolType]::Tls11 -bor `
            [Net.SecurityProtocolType]::Tls
                
        Write-Host "Downloading files"
        #https://stackoverflow.com/questions/50883889/downloading-multiple-files-with-invoke-webrequest
        ForEach ($file in $csv.GetEnumerator()) {
    
            Write-Host "Downloading"$file.url"" -ForegroundColor Cyan
            Invoke-WebRequest -Uri $file.URL -OutFile $file.outfile
            }
        Write-Host
    }
    
    function Unzip-Files {
        ForEach ($item in $csv.GetEnumerator()) {
        
            $destinationPath = $item.destinationPath
            $outFile = $item.outFile
        
            switch ($item.type)
                {
                    script {
                        if ($item.url -like  "*.ps*1") {
                            Write-Host "Skipping PowerShell scripts" -ForegroundColor DarkCyan
                            Write-Host
                            }
                        if ($item.url -like "*.zip") {
                            Write-Host "Unzipping"$outfile"" -ForegroundColor Magenta
                            Expand-Archive -Path $outfile -DestinationPath $destinationPath -Force 
                            }
                    }
                    secbase {
                                if (!(Test-Path -Path $item.destinationpath)) {
                                    Write-Host "Unzipping"$item.outfile"" -ForegroundColor Magenta
                                    Expand-Archive -Path $item.outfile -DestinationPath $item.destinationPath
                                }
                                else {
                                    Write-Host "  "$item.outfile" already exists...not unzipping"
                                    Write-Host
                                }
                    }
                    admx {
                            if (!(Test-Path -Path $item.destinationpath)) {
                                Write-Host "Extracting"$item.outfile"" -ForegroundColor Magenta
                                $msiArgs = "/a " + "`"$outFile`"" + " TARGETDIR=`"$destinationPath`"" + " /qn"
                                Start-Process msiexec -ArgumentList $msiArgs
                                Start-Sleep -Seconds 15
                            }
                            else {
                                Write-Host "  "$item.outfile" already exists...not unzipping"
                                Write-Host
                                }
                     }
                    tool {
                            if ($item.ver -like "*LAPS*") {
                                if (!(Test-Path -Path $item.destinationpath)) {
                                    Write-Host "Extracting"$item.outfile"" -ForegroundColor Magenta
                                    $msiArgs = "/a " + "`"$outFile`"" + " TARGETDIR=`"$destinationPath`"" + " /qn"
                                    Start-Process msiexec -ArgumentList $msiArgs
                                    Start-Sleep -Seconds 15
                                }
                                else {
                                    Write-Host "  "$item.outfile"  already exists...not extracting"
                                    Write-Host
                                    }
                                }   
                            if ($item.ver -like "*Sysmon*") {
                                if (!(Test-Path -Path $item.destinationpath)) {
                                    Write-Host "Unzipping"$item.outfile"" -ForegroundColor Magenta
                                    Expand-Archive -Path $item.outfile -DestinationPath $item.destinationPath
                            }
                                else {
                                    Write-Host "  "$item.outfile" exists...not creating"
                                    Write-Host
                                    }
                            }      
                    }
                }
            }
        }
    
    function Copy-Files {
        Write-Host "Copying scripts and tools to destinations"
        
        Write-Host "  Copying Sysmon"
        $SYSVOLsoftware = "\\$forest\SYSVOL\Software"
        Copy-Item -Path C:\BorgKit\Tools\Sysmon\sysmon*.exe -Destination $SYSVOLsoftware
        Rename-Item -Path C:\BorgKit\Scripts\sysmonconfig-export.xml -NewName sysmonConfig.xml
        Copy-Item -Path C:\BorgKit\Scripts\sysmonConfig.xml -Destination $SYSVOLsoftware
        Write-Host "    Complete" -ForegroundColor Green

        Write-Host "  Copying LAPS"
        Copy-Item -Path C:\BorgKit\Tools\LAPS\x64\LAPS.x64.msi -Destination $SYSVOLsoftware
        Copy-Item -Path C:\BorgKit\Tools\LAPS\x86\LAPS.x86.msi -Destination $SYSVOLsoftware
        Write-Host "    Complete" -ForegroundColor Green
        
        $ADMXbasePath = $csv | Where-Object {$_.type -eq "ADMX"} | Select-Object -ExpandProperty DestinationPath
        #$ADMXpart = $ADMXbasePath.Split('\') | Select-Object -Last 1
        $ADMXpath = $ADMXbasePath + "\Microsoft Group Policy\" + "*" + "\PolicyDefinitions\"
        $ADMLpath = $ADMXpath  + $language

        Write-Host "  Copying ADMX"
        Get-ChildItem -Path $ADMXpath\*.admx | Copy-Item -Destination "\\$forest\SYSVOL\$forest\policies\PolicyDefinitions"
        Write-Host "    Complete" -ForegroundColor Green

        Write-Host "  Copying ADML"
        Get-ChildItem -Path $ADMLpath\*.adml | Copy-Item -Destination "\\$forest\SYSVOL\$forest\policies\PolicyDefinitions\$language"
        Write-Host "    Complete" -ForegroundColor Green

        Write-Host
        Read-Host "press enter to exit"
    }
    
    function Run-PAWScripts {
        $ErrorActionPreference = 'SilentlyContinue'

        #Set the ForestDnsZones Naming Context
        $rootdse = Get-ADRootDSE
        $domainDN = Get-ADDomain | Select-Object -ExpandProperty DistinguaishedName
        $forestDnsZonesDNMatch = "DC=ForestDnsZones," + $domainDN 
    
           do {
            $forestDnsZonesDN = "DC=ForestDnsZones," + $rootDSE.RootDomainNamingContext
            Write-Host "ForestDNSZonesDN is $forestDnsZonesDN"
            Start-Sleep -Seconds 15

        
           } until (($forestDnsZonesDN = "DC=ForestDnsZones," + $rootDSE.RootDomainNamingContext) -is $forestDnsZonesDNMatch) 
    
        $PAWScriptOU = Get-ADOrganizationalUnit -Filter * | Where-Object {$_.DistinguishedName -like "*OU=Groups,OU=Tier 0,OU=Admin*"} | Select-Object DistinguishedName
        $ErrorActionPreference = 'Continue'
        if (!($PAWScriptOU)) {
    
            Write-Host "Running PAWScripts..." -ForegroundColor Yellow
            Set-Location -Path C:\BorgKit\Scripts\PAW
            Start-Sleep -Seconds 15
    
            Write-Host "  Running Create-PAWOUs.ps1" -ForegroundColor Yellow
            Start-Sleep -Seconds 15
            .'C:\BorgKit\Scripts\PAW\Create-PAWOUs.ps1'
            Write-Host "    Complete" -ForegroundColor Green
            
            Write-Host "  Running Create-PAWGroups.ps1" -ForegroundColor Yellow
            Start-Sleep -Seconds 15
            .'C:\BorgKit\scripts\paw\Create-PAWGroups.ps1'
            Write-Host "    Complete" -ForegroundColor Green

            Write-Host "  Running Set-PAWOUDelegation.ps1" -ForegroundColor Yellow
            Start-Sleep -Seconds 15
            .'C:\BorgKit\scripts\PAW\Set-PAWOUDelegation.ps1'
            Write-Host "    Complete" -ForegroundColor Green
            Write-Host
        }
        else
        {
            Write-Host "PAW Scripts already run..." -ForegroundColor Yellow
            Write-Host "    Continuing" -ForegroundColor Green
        }
    }
    
    function Import-SecBaselines {
    
        Import-Module C:\BorgKit\Scripts\Import-SecurityBaselineGPO.ps1

        Write-Host "Importing Security Baselines"
    
        ForEach ($item in $csv.GetEnumerator()) {
    
            if ($item.type -eq "secbase" ) {
            
                $GPOBackupFolder = $item.destinationPath

                if ($item.ver -like "*edgev80*") {

                    $GPOBackupPath = $GPOBackupFolder + "\Microsoft-Edge-v80-Security-Baseline-FINAL" + "\GPOs"
                }
                else {

                    $GPOBackupPath = $GPOBackupFolder + "\GPOs"
                }
    
                Import-SecurityBaselineGPO -GPOBackupPath $GPOBackupPath
        }
            else {

            }
            Write-Host "  Skipping non securitybaseline items" -ForegroundColor DarkCyan
        }
        Write-Host "  Complete" -ForegroundColor Green
    }

    #Task - Create GPOs that secure the PAW
    #function Create-PAWGPOs () {
        #PAW GPOs
        #https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/privileged-access-workstations#create-paw-configuration---computer-group-policy-object-gpo

    #}
    
    #Task - Delegate Bitlocker Computer Permissions on Coomputer OU
    #Create/import Bitlocker Policy
    #https://adameyob.com/2016/12/08/zero-touch-bitlocker-deployments/
    #https://github.com/TechWhispererCA/BitLocker-AutoEnable
    
    #Task - Deploy LAPS
    #https://www.starwindsoftware.com/blog/deploying-microsoft-laps
    #https://github.com/Sup3rlativ3/Deploy-LAPS
    
    function Cleanup-BorgKit {
    
        Remove-Item C:\BorgKit\Scripts\locutus.txt
    
    }
    
    function Set-GPOLinks {
        Start-Sleep -Seconds 30

        Write-Host "Linking GPOs..."
        $rootdse = Get-ADRootDSE
        $baseOU = $rootDSE.RootDomainNamingContext
        
        $userAccountsOU = "OU=User Accounts," + $baseOU
        $workstationsOU = "OU=Workstations," + $baseOU
        $computerQuarantineOU = "OU=Computer Quarantine," + $baseOU
        $tier1ServersOU = "OU=Tier 1 Servers," + $baseOU
        $PAWDevicesOU = "OU=Devices,OU=Tier 0,OU=Admin," + $baseOU
        $domainControllersOU = "OU=Domain Controllers," + $baseOU

        $GPOs = Get-GPO -All | Select-Object -ExpandProperty DisplayName
        #Write-Host "Domain conttolers OU is $domaincontrollersOU"
        #Write-Host "GPos are "
        #Write-host "$GPOs"
        #read-host "press enter"
        
        $edgev80 =  $GPOs | Where-Object {$_ -like "*Edge Version 80 - Computer"}

        $iE11computer = $GPOs | Where-Object {$_ -like "*11 - Computer"}
        $iE11user = $GPOs | Where-Object {$_ -like "*11 - User"}
        
        $officeComputer  = $GPOs | Where-Object {$_-like "*1908 - Computer"}
        $officeExcelDDEBlock = $GPOs | Where-Object {$_ -like "*1908 - Excel DDE Block*"}
        $officeLegacyFileBlock  = $GPOs | Where-Object {$_ -like "*1908 - Legacy File Block*"}
        $officeRequireMacro  = $GPOs | Where-Object {$_ -like "*1908 - Require Macro Signing*"}
        $officeUser  = $GPOs | Where-Object {$_ -like "*1908 - User*"}

        $win10Bitlocker  = $GPOs | Where-Object {$_ -like "*1909 - Bitlocker"}
        $win10Computer  = $GPOs | Where-Object {$_ -like "*1909 - Computer*"}
        $win10User  = $GPOs | Where-Object {$_ -like "*1909 - User"}
        $win10Defender = $GPOs | Where-Object {$_ -like "*1909 - Defender Antivirus*"}
        $win10DomainSecurity = $GPOs | Where-Object {$_ -like "*1909 - Domain Security"}
        $win10MemberSVRCredGuard = $GPOs | Where-Object {$_ -like "*- Credential Guard*"}

        $winSvrDC = $GPOs | Where-Object {$_ -like "*1909 - Domain Controller"}
        $winSvrDCVirtSec = $GPOs | Where-Object {$_ -like "*1909 - Domain Controller Virtualization*"}
        $winMemberSvr = $GPOs | Where-Object {$_ -like "*1909 - Member Server"}

        New-GPLink -Name $win10DomainSecurity -Target $baseOU -LinkEnabled Yes
        
        New-GPLink -Name $winSvrDC -Target $domainControllersOU -LinkEnabled Yes
        New-GPLink -Name $winSvrDCVirtSec -Target $domainControllersOU -LinkEnabled Yes
        
        New-GPLink -Name $edgev80 -Target $tier1ServersOU -LinkEnabled Yes
        New-GPLink -Name $iE11computer -Target $tier1ServersOU -LinkEnabled Yes
        New-GPLink -Name $win10MemberSVRCredGuard -Target $tier1ServersOU -LinkEnabled Yes
        New-GPLink -Name $winMemberSvr -Target $tier1ServersOU -LinkEnabled Yes

        New-GPLink -Name $iE11user -Target $userAccountsOU -LinkEnabled Yes
        New-GPLink -Name $officeExcelDDEBlock -Target $userAccountsOU -LinkEnabled Yes
        New-GPLink -Name $officeLegacyFileBlock -Target $userAccountsOU -LinkEnabled Yes
        New-GPLink -Name $officeRequireMacro -Target $userAccountsOU -LinkEnabled Yes
        New-GPLink -Name $officeUser -Target $userAccountsOU -LinkEnabled Yes
        New-GPLink -Name $win10User -Target $userAccountsOU -LinkEnabled Yes

        New-GPLink -Name $edgev80 -Target $workstationsOU -LinkEnabled Yes
        New-GPLink -Name $iE11computer -Target $workstationsOU -LinkEnabled Yes
        New-GPLink -Name $officeComputer -Target $workstationsOU -LinkEnabled Yes
        New-GPLink -Name $win10Bitlocker -Target $workstationsOU -LinkEnabled Yes
        New-GPLink -Name $win10Computer -Target $workstationsOU -LinkEnabled Yes
        New-GPLink -Name $win10Defender -Target $workstationsOU -LinkEnabled Yes

        Write-Host "  Complete" -ForegroundColor Green
    }

    #Task - Create GPOs and Scheduled Task for software installs
    #function Scheduled-Tasks  {
        #Sysmon
        #https://www.syspanda.com/index.php/2017/02/28/deploying-sysmon-through-gpo/
        #$sysmonBAT = Get-Content C:\scripts\sysmonInstall.bat
        #$sysmonBAT.Replace("domain.com","$forest") 

        #LAPS
        #$LAPSBAT = Get-Content C:\scripts\LAPSInstall.bat

    #}

    function Resume-Script {
        
        $script:language = "en-us"
        $script:version = '1909'
        $script:forest = Get-ADDomain | Select-Object -ExpandProperty Forest
        $script:forstDN = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
        $script:csv = Import-Csv "C:\borgKit\Scripts\borgCube.csv"
        
    }
    # Task - Setup Install of LAPS PW Reader
    #function Install-Programs {

        #Install LAPS PW Reader
        
    #}
    
    #Task - Secure the 'Administrator' domain account
    #function Secure-Users  {

        #Add Administrator to protected users
        #Remove from interactive login?

    #}

    #region Start Script
    
    Check-Bookmark
    
    switch ($status) {
        new  {
            Create-BorgKitFolders
            Download-BorgCube
            Download-Files
            Unzip-Files
            RSAT-Prereqs
            Domain-Prereqs
        }
        continue {
            Resume-Script
            Create-PolicyFolders
            Run-PAWScripts
            Import-SecBaselines
            Set-GPOLinks
            Copy-Files
            Cleanup-BorgKit
        }
    }
    #endregion
}
Invoke-BorgKit