Param (
    [string]$path = $null
)

Function PSasAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $result = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return $result
}

Function RunMDEClientAnalyzer {
    $url = "https://aka.ms/BetaMDEAnalyzer"
    mkdir ($script:LogPath + "\..\tools\") | Out-Null
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest $url -UseBasicParsing -OutFile ($script:LogPath + "\..\tools\mdeclient.zip")
    Expand-Archive ($script:LogPath + "\..\tools\mdeclient.zip") -DestinationPath ($script:LogPath + "\..\tools\") -Force
    &($script:LogPath + "\..\tools\MDEClientAnalyzer.cmd")
    Move-Item -Path ($script:LogPath + "\..\tools\MDEClientAnalyzerResult\") -Destination ($script:LogPath + "\MDEClientAnalyzerResult\")
    $script:MDEAnalizerResultPath = ($script:LogPath + "\MDEClientAnalyzerResult")
}

Function TestConfigMgr {
    $ErrorActionPreference = 'silentlycontinue'
    $ccmService = Get-Service CcmExec
    if ($null -ne $ccmService) {
        #Write-Log INFO ("ConfigMgr client is installed, startup: "+$ccmService.StartType+" status: "+$ccmService.Status)
        
        #$script:checks.Management.Add("ConfigMgr", @{Installed = "YES" ; StartType = $ccmService.StartType ; Status = $ccmService.Status })
        report "Management.ConfigMgr.Installed" "YES" $script:checks    
        report "Management.ConfigMgr.StartType" $ccmService.StartType $script:checks    
        report "Management.ConfigMgr.Status" $ccmService.Status $script:checks    
    }
    else {
        #$script:checks.Management.Add("ConfigMgr", @{Installed = "NO" ; StartType = "" ; Status = "" })
        report "Management.ConfigMgr.Installed" "NO" $script:checks    
    }
    $ErrorActionPreference = 'continue'
}

function CheckMDAVConfig {
    #if conf check has not been done already do it, else just quit

    if ($script:checks.MDAV.Keys -contains "Config") {
        return
    }
    
    #Get the MDAV Support package
    $MDAVBinPath = ""
    if (Test-Path "C:\ProgramData\Microsoft\Windows Defender\Platform\") {
        $MDAVBinPath = "C:\ProgramData\Microsoft\Windows Defender\Platform\"
        $versions = Get-ChildItem $MDAVBinPath
        if ($null -ne $versions) {
            $MDAVBinDir = ($versions | Sort-Object -Property LastWriteTime -Descending)[0].FullName
            if (Test-Path ($MDAVBinDir + "\Mpcmdrun.exe")) {
                $MDAVBin = ($MDAVBinDir + "\Mpcmdrun.exe")
                report "MDAV.BinaryVersion" (Get-Item $MDAVBin).VersionInfo.FileVersion $script:checks
            }
        }
        elseif (Test-Path "C:\Program Files\Windows Defender\") {
            $MDAVBinDir = "C:\Program Files\Windows Defender\"
            if (Test-Path ($MDAVBinDir + "\Mpcmdrun.exe")) {
                $MDAVBin = ($MDAVBinDir + "\Mpcmdrun.exe")
                report "MDAV.BinaryVersion" (Get-Item $MDAVBin).VersionInfo.FileVersion $script:checks
            }
            report "Error.MDAV.EngineNotUpdated" "" $script:checks
        }
   
    }
    elseif (Test-Path "C:\Program Files\Windows Defender\") {
        $MDAVBinPath = "C:\Program Files\Windows Defender\"
        $versions = Get-ChildItem $MDAVBinPath
        $MDAVBinDir = ($versions | Sort-Object -Property LastWriteTime -Descending)[0].FullName
        if (Test-Path ($MDAVBinDir + "\Mpcmdrun.exe")) {
            $MDAVBin = ($MDAVBinDir + "\Mpcmdrun.exe")
            report "MDAV.BinaryVersion" (get-file $MDAVBin).VersionInfo.FileVersion $script:checks
        }
        report "Error.MDAV.EngineNotUpdated" "" $script:checks
    }


    if ($null -ne $MDAVBin) {
        & $MDAVBin -GetFiles -SupportLogLocation ($script:LogPath + "\tools\MDAVDIAG\")
        if (Test-Path ($script:LogPath + "\tools\MDAVDIAG")) {
            $archivePath = (Get-ChildItem ($script:LogPath + "\tools\MDAVDIAG\*\*.cab"))[0].FullName
            expand -I $archivePath -F:* ($script:LogPath + "\tools\MDAVDIAG\")
        }
        else {
            mkdir ($script:LogPath + "\tools\MDAVDIAG") | out-null
            $archivePath = (Get-ChildItem "C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab").FullName    
            expand -I $archivePath -F:* ($script:LogPath + "\tools\MDAVDIAG\")
        }
        if (Test-Path ($script:LogPath + "\tools\MDAVDIAG\MPRegistry.txt")) {
            $registry = Get-Content ($script:LogPath + "\tools\MDAVDIAG\MPRegistry.txt")
            $max = $registry.Length
            $cpt = 0
            $cptfound = 0
            $registryconf = @{}
            $registryKeyToCheck = @("DisableAntiSpyware", "DisableAntiVirus", "DisableBehaviorMonitoring", "PassiveMode")
            
            do {
                $current = $registry[$cpt]
                
                foreach ($value in $registryKeyToCheck) {
                    
                    if ($current -match "^\s+($value)\s+(\[REG_.*])\s+:(.*)$") {  
                        if (!($registryconf.Keys -contains $value)) {
                            $registryconf.Add($value, $matches[3].Trim())
                        }
                        if ( ($value -in @("DisableAntiSpyware", "DisableAntiVirus", "DisableBehaviorMonitoring")) -and ($matches[3].Trim() -ne "0 (0X0)") ) {
                            #if(!($script:checks.Errors.Keys -contains "MDAV"))
                            #{
                            #    #$script:checks.Errors.Add("MDAV",@{})
                            #}
                            if (!($script:checks.Error.MDAV.Keys -contains $value)) {
                                #$script:checks.Errors.MDAV.Add($value,"AV disabled by registry")
                                report "Error.MDAV.$value" "AV disabled by registry" $script:checks
                            }
                        }
                        $cptfound++
                    }
                    
                }
                $cpt++
            } while (($cptfound -lt $registryKeyToCheck.Length) -and ($cpt -lt $max))


            #if(!($script:checks.MDAV.Keys -contains "Config"))
            #{
            #$script:checks.MDAV.Add("Config", $registryconf)
            report "MDAV.Config" $registryconf $script:checks
            #}
        }

        CheckThirdPartyAV
    
    }
    else {
        #if(!($script:checks.Errors.Keys -contains "MDAV"))
        #{
        #    $script:checks.Errors.Add("MDAV",@{})
        #}
        #$script:checks.Errors.MDAV.Add("Binaries","Binaries not found")
        report "Error.MDAV.Binaries" "Binaries not found" $script:checks
    }

    $mpresults = Get-MpPreference
    if ($mpresults.DisableRealtimeMonitoring) {
        report "MDAV.config.RealtimeMonitoring" "Disabled" $script:checks 
    }
    else {
        report "MDAV.config.RealtimeMonitoring" "Enabled" $script:checks 
    }

    if ($mpresults.DisableBehaviorMonitoring) {
        report "MDAV.config.BehaviorMonitoring" "Disabled" $script:checks 
    }
    else {
        report "MDAV.config.BehaviorMonitoring" "Enabled" $script:checks 
    }

    switch ($mpresults.MAPSReporting) {
        0 { report "MDAV.config.MAPSReporting" "Disabled" $script:checks ; break }
        1 { report "MDAV.config.MAPSReporting" "Basic" $script:checks ; break }
        2 { report "MDAV.config.MAPSReporting" "Advanced" $script:checks; break }
        default { break }
    }

    
}

Function CheckThirdPartyAV {
    if ($script:checks.MDAV.Keys -contains "WSCConfig") {
        return
    }
    if (Test-Path ($script:LogPath + "\tools\MDAVDIAG\WSCInfo.txt")) {
        $WSCcontent = get-content ($script:LogPath + "\tools\MDAVDIAG\WSCInfo.txt")

        $max = $WSCcontent.Length
        $cpt = 0
        $WSCconf = @{}
        
        $AVSectionOn = $false
        $FWSectionOn = $false
        $AVcpt = 0
        $FWcpt = 0
        do {
            $current = $WSCcontent[$cpt]
                
            if ($current -match "^.*(WSC_SECURITY_PROVIDER_ANTIVIRUS).*$") {
                $AVSectionOn = $true
                $FWSectionOn = $false
            }
            elseif ($current -match "^.*(WSC_SECURITY_PROVIDER_FIREWALL).*$") {
                $FWSectionOn = $true
                $AVSectionOn = $false
            }
            elseif ($AVSectionOn) {
                if ($current -match "^\s+(Name:)\s+(.*)$") {
                    $AVcpt++
                    $WSCconf.Add("AV-$AVcpt", @{})
                    $WSCconf."AV-$AVcpt".Add("Name", $matches[2])
                }
                elseif ($current -match "^\s+(State:)\s+(.*)$") {
                    $WSCconf."AV-$AVcpt".Add("State", $matches[2])
                }
            }
            elseif ($FWSectionOn) {
                if ($current -match "^\s+(Name:)\s+(.*)$") {
                    $FWcpt++
                    $WSCconf.Add("FW-$FWcpt", @{})
                    $WSCconf."FW-$FWcpt".Add("Name", $matches[2])
                }
                elseif ($current -match "^\s+(State:)\s+(.*)$") {
                    $WSCconf."FW-$FWcpt".Add("State", $matches[2])
                }
            }
            $cpt++
        } while (($cpt -lt $max))

        #$script:checks.MDAV.Add("WindowsSecurityCenter", $WSCconf)
        report "MDAV.WindowsSecurityCenter" $WSCconf $script:checks
    }
}

Function Test-DevRegApp {
    #Write-Host ''
    #Write-Host "Testing Device Registration Service..." -ForegroundColor Yellow
    $headers = @{ 
        'Content-Type'  = "application\json"
        'Authorization' = "Bearer $script:accesstoken"
    }
    $GraphLink = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9'"
    $GraphResult = ""
    $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json

    if ($GraphResult.value.accountenabled) {
        Write-Host "Test passed: Device Registration Service is enabled on the tenant" -ForegroundColor Green 
        report "DeviceIdentity.AzureActiveDirectory.DeviceRegistration" "Enabled" $script:checks
    }
    else {
        Write-Host "Test failed: Device Registration Service is disabled on the tenant" -ForegroundColor red
        report "Error.DeviceIdentity.AzureActiveDirectory.DeviceRegistration" "Disabled" $script:checks
        report "DeviceIdentity.AzureActiveDirectory.DeviceRegistration" "Disabled" $script:checks

        #Write-Host ''
        #Write-Host "Recommended action: enable Device Registration Service application on your tenant" -ForegroundColor Yellow                        
    }
}

Function SyncJoinCheck($Fallback) {

    if ($Fallback) {
        #Write-Host ''
        #Write-Host ''
        Write-Host "Federated join flow failed, checking Sync join flow..."
        

        #Check OS version:
        Write-Host ''
        Write-Host "Testing OS version..." -ForegroundColor Yellow
        
        $OSVersion = ([environment]::OSVersion.Version).major
        $OSBuild = ([environment]::OSVersion.Version).Build
        if (($OSVersion -ge 10) -and ($OSBuild -ge 17134)) {
            #17134 build is 1803
            $OSVer = (([environment]::OSVersion).Version).ToString()
            Write-Host "Test passed: OS version supports fallback to sync join" -ForegroundColor Green
            
        }
        else {
            # dsregcmd will not work.
            Write-Host "OS version does not support fallback to sync join, hence device registration will not complete" -ForegroundColor Red
            report "Error.DeviceIdentity.ActiveDirectory.SyncJoinFallBack" "KO" $script:checks
            report "DeviceIdentity.ActiveDirectory.SyncJoinFallBack" "OS version $OSVersion.$OSBuild too old" $script:checks
            #Write-Host ''
            #Write-Host "Recommended action: Fallback to sync join enabled by default on 1803 version and above" -ForegroundColor Yellow   
            return         
        }

        #Checking FallbackToSyncJoin enablement
        #Write-Host ''
        #Write-Host "Checking fallback to sync join configuration..." -ForegroundColor Yellow

        $reg = Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ' -ErrorAction SilentlyContinue
        if ($reg.FallbackToSyncJoin -eq 0) {
            Write-Host "Test failed: Fallback to sync join is disabled" -ForegroundColor Red
            report "Error.DeviceIdentity.ActiveDirectory.SyncJoinFallBack" "KO" $script:checks
            report "DeviceIdentity.ActiveDirectory.SyncJoinFallBack" "Fallback to sync joined is disabled" $script:checks
            #$script:checks.Errors.ActiveDirectory.Add("SyncJoinedEnabled", "Failed")
            #$script:checks.Device.ActiveDirectory.Add("SyncJoinedEnabled", "KO")
            #Write-Host ''
            #Write-Host "Recommended action: Make sure that FallbackToSyncJoin is not disabled so that device fall back to sync join flow in case federated join flow failed" -ForegroundColor Yellow
            #Write-Host "                    This can be done by removing 'FallbackToSyncJoin' registry value under 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin'" -ForegroundColor Yellow
            
        }
        else {
            Write-Host "Fallback to sync join is enabled" -ForegroundColor Green
            #$script:checks.Device.ActiveDirectory.Add("SyncJoinedEnabled", "OK")
            report "DeviceIdentity.ActiveDirectory.SyncJoinFallBack" "Enabled" $script:checks
        }
    }
    
    #Get device object GUID
    $DN = ([adsisearcher]"(&(objectCategory=computer)(objectClass=computer)(cn=$env:COMPUTERNAME))").findall().path
    $OGuid = ([ADSI]$DN).ObjectGuid
    $ComputerGUID = (new-object guid(, $OGuid[0])).Guid
        
    #Checking userCert
    #Write-Host ''
    #Write-Host "Testing userCertificate attribute under AD computer object..." -ForegroundColor Yellow


    if ($script:UserUPN.Length -ne 0) {

        $ValidUserCertExist = $false
        $userCerts = ([adsisearcher]"(&(name=$env:computername)(objectClass=computer))").findall().Properties.usercertificate
        $userCertCount = $userCerts.count
        if ($userCertCount -ge 1) {
            #Write-Host "AD computer object has $userCertCount certificate(s) under userCertificate attribute" -ForegroundColor Green
            #
            #Write-Host ''
            #Write-Host "Testing self-signed certificate validity..." -ForegroundColor Yellow

            foreach ($userCert in $userCerts) {
                $userCert = (new-object X509Certificate(, $userCert))
                $certSubject = ($userCert.Subject.tostring() -split "CN=")[1].trim()
                If ($certSubject -eq $ComputerGUID) {
                    $ValidUserCertExist = $true
                }
            }
        }
        else {
            #No userCert exist
            Write-Host "Test failed: There is no userCertificate under AD computer object" -ForegroundColor Red
            report "Warning.DeviceIdentity.ActiveDirectory.ADUserCert" "KO" $script:checks
            report "DeviceIdentity.ActiveDirectory.ADUserCert" "KO" $script:checks
            #$script:checks.Errors.ActiveDirectory.Add("ADUserCert", "Failed")
            #$script:checks.Device.ActiveDirectory.Add("ADUserCert", "KO")
            #Write-Host ''
            #Write-Host "Recommended action: Make sure to start device registration process, and the device has permission to write self-signed certificate under AD computer object" -ForegroundColor Yellow            
        }
        if ($ValidUserCertExist) {
            Write-Host "Test passed: AD computer object has a valid self-signed certificate" -ForegroundColor Green
            #$script:checks.Device.ActiveDirectory.Add("ADUserCert", "OK")
            report "DeviceIdentity.ActiveDirectory.ADUserCert" "OK" $script:checks

        }
        else {
            Write-Host "Test failed: There is no valid self-signed certificate under AD computer object userCertificate attribute" -ForegroundColor Red
            report "Warning.DeviceIdentity.ActiveDirectory.ADUserCert" "KO" $script:checks
            report "DeviceIdentity.ActiveDirectory.ADUserCert" "KO" $script:checks
            #$script:checks.Errors.ActiveDirectory.Add("ADUserCert", "Failed")
            #$script:checks.Device.ActiveDirectory.Add("ADUserCert", "KO")
            #Write-Host ''
            #Write-Host "Recommended action: Make sure to start device registration process, and the device has permission to write self-signed certificate under AD computer object" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "Test failed: signed in user is not a domain user, you should sign in with domain user to perform this test" -ForegroundColor Yellow
        report "Error.DeviceIdentity.ActiveDirectory.DomainUser" "KO" $script:checks
        #$script:checks.Errors.ActiveDirectory.Add("DomainUser", "Failed")

    }

    #Checking if device synced
    ConnecttoAzureAD
    #Write-Host ''
    #Write-Host "Testing if the device synced to Azure AD..." -ForegroundColor Yellow
    
    $headers = @{ 
        'Content-Type'  = "application\json"
        'Authorization' = "Bearer $script:accesstoken"
    }
    $GraphLink = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$ComputerGUID'"
    $GraphResult = Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json"
    $AADDevice = $GraphResult.Content | ConvertFrom-Json
    if ($AADDevice.value.Count -ge 1) {
        #The device existing in AAD:
        Write-Host "Test passed: the device object exists on Azure AD" -ForegroundColor Green
        report "DeviceIdentity.ActiveDirectory.DeviceSyncedinAAD" "OK" $script:checks
        #$script:checks.Device.ActiveDirectory.Add("DeviceSyncedinAAD", "OK")
    }
    else {
        #Device does not exist:
        ###Reregister device to AAD
        Write-Host "Test failed: the device does not exist in your Azure AD tenant" -ForegroundColor Red
        report "Warning.DeviceIdentity.ActiveDirectory.DeviceSyncedinAAD" "KO" $script:checks
        report "DeviceIdentity.ActiveDirectory.DeviceSyncedinAAD" "KO" $script:checks

        #$script:checks.Errors.ActiveDirectory.Add("DeviceSyncedinAAD", "Failed")
        #$script:checks.Device.ActiveDirectory.Add("DeviceSyncedinAAD", "KO")
        #$DeviceDN = ((([adsisearcher]"(&(name=$env:computername)(objectClass=computer))").findall().path).tostring() -split "LDAP://")[1].trim()
        #Write-Host ''
        #Write-Host "Recommended action: Make sure the device is in the sync scope, and it is successfully exported to Azure AD by Azure AD Connect." -ForegroundColor Yellow
        #Write-Host "Device DN: $DeviceDN" -ForegroundColor Yellow

    }
}

function Connect-AzureDevicelogin {
    [cmdletbinding()]
    param( 
        [Parameter()]
        $ClientID = '1950a258-227b-4e31-a9cf-717495945fc2',
        
        [Parameter()]
        [switch]$Interactive,
        
        [Parameter()]
        $TenantID = 'common',
        
        [Parameter()]
        $Resource = "https://graph.microsoft.com/",
        
        # Timeout in seconds to wait for user to complete sign in process
        [Parameter(DontShow)]
        $Timeout = 1
        #$Timeout = 300
    )
    try {
        $DeviceCodeRequestParams = @{
            Method = 'POST'
            Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/devicecode"
            Body   = @{
                resource     = $Resource
                client_id    = $ClientId
                redirect_uri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
            }
        }
        $DeviceCodeRequest = Invoke-RestMethod @DeviceCodeRequestParams
 
        # Copy device code to clipboard
        $DeviceCode = ($DeviceCodeRequest.message -split "code " | Select-Object -Last 1) -split " to authenticate."
        Set-Clipboard -Value $DeviceCode

        Write-Host ''
        Write-Host "Device code " -ForegroundColor Yellow -NoNewline
        Write-Host $DeviceCode -ForegroundColor Green -NoNewline
        Write-Host "has been copied to the clipboard, please paste it into the opened 'Microsoft Graph Authentication' window, complete the sign in, and close the window to proceed." -ForegroundColor Yellow
        Write-Host "Note: If 'Microsoft Graph Authentication' window didn't open,"($DeviceCodeRequest.message -split "To sign in, " | Select-Object -Last 1) -ForegroundColor gray
        $msg = "Device code $DeviceCode has been copied to the clipboard, please paste it into the opened 'Microsoft Graph Authentication' window, complete the signin, and close the window to proceed.`n                                 Note: If 'Microsoft Graph Authentication' window didn't open," + ($DeviceCodeRequest.message -split "To sign in, " | Select-Object -Last 1)
        

        # Open Authentication form window
        Add-Type -AssemblyName System.Windows.Forms
        $form = New-Object -TypeName System.Windows.Forms.Form -Property @{ Width = 440; Height = 640 }
        $web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ Width = 440; Height = 600; Url = "https://www.microsoft.com/devicelogin" }
        $web.Add_DocumentCompleted($DocComp)
        $web.DocumentText
        $form.Controls.Add($web)
        $form.Add_Shown({ $form.Activate() })
        $web.ScriptErrorsSuppressed = $true
        $form.AutoScaleMode = 'Dpi'
        $form.text = "Microsoft Graph Authentication"
        $form.ShowIcon = $False
        $form.AutoSizeMode = 'GrowAndShrink'
        $Form.StartPosition = 'CenterScreen'
        $form.ShowDialog() | Out-Null
        
        $TokenRequestParams = @{
            Method = 'POST'
            Uri    = "https://login.microsoftonline.com/$TenantId/oauth2/token"
            Body   = @{
                grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                code       = $DeviceCodeRequest.device_code
                client_id  = $ClientId
            }
        }
        $TimeoutTimer = [System.Diagnostics.Stopwatch]::StartNew()
        while ([string]::IsNullOrEmpty($TokenRequest.access_token)) {
            if ($TimeoutTimer.Elapsed.TotalSeconds -gt $Timeout) {
                throw 'Login timed out, please try again.'
            }
            $TokenRequest = try {
                Invoke-RestMethod @TokenRequestParams -ErrorAction Stop
            }
            catch {
                if ($null -ne $_.ErrorDetails.Message) {
                    $Message = $_.ErrorDetails.Message | ConvertFrom-Json
                    if ($Message.error -ne "authorization_pending") {
                        throw
                    }
                }
                else {
                    throw
                }
            }
            Start-Sleep -Seconds 1
        }
        Write-Output $TokenRequest.access_token
    }
    finally {
        try {
            Remove-Item -Path $TempPage.FullName -Force -ErrorAction Stop
            $TimeoutTimer.Stop()
        }
        catch {
            #Ignore errors here
        }
    }
}

Function ConnecttoAzureAD {
    #Write-Host ''
    #Write-Host "Checking if there is a valid Access Token..." -ForegroundColor Yellow
    
    $headers = @{ 
        'Content-Type'  = "application\json"
        'Authorization' = "Bearer $script:accesstoken"
    }
    $GraphLink = "https://graph.microsoft.com/v1.0/domains"
    $GraphResult = ""
    $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json

    if ($GraphResult.value.Count) {
        $headers = @{ 
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $script:accesstoken"
        }
        $GraphLink = "https://graph.microsoft.com/v1.0/me"
        $GraphResult = ""
        $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
        $User_DisplayName = $GraphResult.displayName
        $User_UPN = $GraphResult.userPrincipalName
        Write-Host "There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" -ForegroundColor Green
        #$msg = "There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" 
    

    }
    else {
        Write-Host "There no valid Access Token, please sign-in to get an Access Token" -ForegroundColor Yellow
    
        $script:accesstoken = Connect-AzureDevicelogin
    
        if ($script:accesstoken.Length -ge 1) {
            $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $script:accesstoken"
            }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult = ""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName = $GraphResult.displayName
            $User_UPN = $GraphResult.userPrincipalName
            Write-Host "You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" -ForegroundColor Green
            #$msg = "You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" 
    
        }
    }

}

# Initialize XML log - for consumption by external parser
function InitXmlLog($path) {
    $script:xmlDoc = [xml](get-content $path)
    $ProdPOCNode = $script:xmlDoc.CreateNode("element", "ProductionPOC", "") 
    $script:xmlDoc.MDEResults.AppendChild($ProdPOCNode) | Out-Null
    $ProdPOCNode = $script:xmlDoc.CreateNode("element", "AVDetailsInfo", "") 
    $script:xmlDoc.MDEResults.AppendChild($ProdPOCNode) | Out-Null
    $ProdPOCNode = $script:xmlDoc.CreateNode("element", "FWDetailsInfo", "") 
    $script:xmlDoc.MDEResults.AppendChild($ProdPOCNode) | Out-Null
    #$script:xmlDoc = [xml]"<?xml version=""1.0"" encoding=""utf-8""?><MDEResults><general></general><ProductionPOC></ProductionPOC><DeviceIdentity></DeviceIdentity><MDAV></MDAV><MDE></MDE><OS></OS><Management></Management><Network></Network><events></events></MDEResults>"
}

function Write-Report($section, $subsection, $displayName, $value, $alert) { 
    $subsectionNode = $script:xmlDoc.CreateNode("element", $subsection, "")    
    $subsectionNode.SetAttribute("displayName", $displayName)

    $eventContext1 = $script:xmlDoc.CreateNode("element", "value", "")
    $eventContext1.psbase.InnerText = $value
    $subsectionNode.AppendChild($eventContext1) | out-Null

    if ($value -eq "Running") {
        $alert = "None"
    }
    elseif (($value -eq "Stopped" -or $value -eq "StartPending")) {
        $alert = "High"
    }

    if ($alert) {
        $eventContext2 = $script:xmlDoc.CreateNode("element", "alert", "")
        $eventContext2.psbase.InnerText = $alert
        $subsectionNode.AppendChild($eventContext2) | out-Null
    }

    $checkresult = $DisplayName + ": " + $value
    # Write message to the ConnectivityCheckFile
    #$checkresult | Out-File $connectivityCheckFile -append

    $xmlRoot = $script:xmlDoc.SelectNodes("/MDEResults")
    $InputNode = $xmlRoot.SelectSingleNode($section)
    $InputNode.AppendChild($subsectionNode) | Out-Null
    return
}

Function report($keypath, $value, $hash = $null, $alert = "", $child = $false) {

    
    Write-Debug "Write report for $keypath with $value"

    if ($keypath -match "^([A-z0-9\ \-]+)\.(.*)$") {
        if (!($hash.Keys -contains $matches[1])) {
            Write-Debug ("add " + $matches[1])
            $hash.Add($matches[1], @{})
        }
        #Write-Debug ("recursive call with "+$matches[2]+" "+$value+" for child of "+$matches[1])
        report $matches[2] $value $hash.Item($matches[1]) $alert $true
    }
    else {
        if ($hash.Keys -contains $keypath) {
            #handle potential duplicate keys, if the value is different, then add it, else do nothing
            if ($value -ne $($hash[$keypath])) {
                $cpt = 0
                $hash.Keys | foreach {
                    if ($_ -match ("^" + $keypath + "(_[1-9]+)?$")) {
                        $cpt++
                    }
                }

                $hash.Add(($keypath + "_" + $cpt), $value)
            }
        }
        else {
            $hash.Add($keypath, $value)
        }
        
    }

    
}

Function VerifySCP {
    #Check client-side registry setting for SCP
    $SCPClient = $false
    Write-Host ''
    Write-Host "Testing client-side registry setting for SCP..." -ForegroundColor Yellow
    
    $Reg = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD -ErrorAction SilentlyContinue
    if (((($Reg.TenantId).Length) -eq 0) -AND ((($Reg.TenantName).Length) -eq 0)) {
        Write-Host "Client-side registry setting for SCP is not configured" -ForegroundColor Yellow
        report "DeviceIdentity.SCPClientSide.ConfCheck" "NotConfigured" $script:checks    
    }
    else {
        $SCPClient = $true
        Write-Host "Client-side registry setting for SCP is configured as the following:" -ForegroundColor Green
        report "DeviceIdentity.SCPClientSide.TenantId" $Reg.TenantId $script:checks
        report "DeviceIdentity.SCPClientSide.TenantName" $Reg.TenantName $script:checks

        #Write-Host "TenantId:" $Reg.TenantId
        $Reg_TenantId = "TenantId:" + $Reg.TenantId
    
        $script:TenantName = $Reg.TenantName
        #Write-Host "TenantName:" $Reg.TenantName
        $Reg_TenantName = "TenantName:" + $Reg.TenantName
    
        #Check client-side SCP info
        Write-Host ''
        Write-Host "Testing client-side registry configuration..." -ForegroundColor Yellow
    
        
        #CheckMSOnline
        #Checking tenant name
        Write-Host ''
        Write-Host "Testing Tenant Name..." -ForegroundColor Yellow
    
        $RegTenantName = $Reg.TenantName
        $InvokeResult = ""
        $InvokeResult = (Invoke-WebRequest -Uri "https://login.microsoftonline.com/$RegTenantName/.well-known/openid-configuration" -UseBasicParsing).content | ConvertFrom-Json
        if ($InvokeResult) {
            $TenantID = ($InvokeResult.issuer.tostring() -split "https://sts.windows.net/")[1].trim()
            $TenantID = ($TenantID.tostring() -split "/")[0].trim()
            #Write-Host "Tenant Name is configured correctly" -ForegroundColor Green
            #
            #Write-Host ''
            #Write-Host "Testing Tenant ID..." -ForegroundColor Yellow
    
            if ($TenantID -eq $Reg.TenantId) {
                Write-Host "Tenant ID is configured correctly" -ForegroundColor Green
                report "DeviceIdentity.SCPClientSide.ConfCheck" "OK" $script:checks
            }
            else {
                Write-Host "Test failed: Tenant ID is not configured correctly" -ForegroundColor Red
                report "DeviceIdentity.SCPClientSide.ConfCheck" "KO" $script:checks
                report "Error.DeviceIdentity.SCPClientSide.ConfCheck" "KO" $script:checks
                #Write-Host ''
                #Write-Host "Recommended action: Make sure the Tenant ID is configured correctly in registry." -ForegroundColor Yellow
                #Write-Host "Registry Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD" -ForegroundColor Yellow                
            }
        }
        else {
            Write-Host "Test failed: Tenant Name is not configured correctly" -ForegroundColor Red
            report "DeviceIdentity.SCPClientSide.ConfCheck" "KO" $script:checks
            report "Error.DeviceIdentity.SCPClientSide.ConfCheck" "KO" $script:checks

            #Write-Host ''
            #Write-Host "Recommended action: Make sure the Tenant Name is configured correctly in registry" -ForegroundColor Yellow
            #Write-Host "Registry Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD" -ForegroundColor Yellow            
        }
    }

    #Check connectivity to DC
    $script:DCTestPerformed = $true
    Write-Host ''
    Write-Host "Testing Domain Controller connectivity..." -ForegroundColor Yellow
    
    $DCName = ""
    $DCTest = nltest /dsgetdc:
    $DCName = $DCTest | Select-String DC | Select-Object -first 1
    $DCName = ($DCName.tostring() -split "DC: \\")[1].trim()
    if (($DCName.length) -eq 0) {
        Write-Host "Test failed: connection to Domain Controller failed" -ForegroundColor Red
        report "Error.DeviceIdentity.ActiveDirectory.DSGETDC" "KO" $script:checks
        #Write-Host ''
        #Write-Host "Recommended action: Make sure that the device has a line of sight connection to the Domain controller" -ForegroundColor Yellow
    
    }
    else {
        Write-Host "Test passed: connection to Domain Controller succeeded" -ForegroundColor Green
        report "DeviceIdentity.ActiveDirectory.DSGETDC" $DCName $script:checks
    }


    #Check SCP
    if ($SCPClient -eq $false) {
        Write-Host ''
        Write-Host "Checking Service Connection Point (SCP)..." -ForegroundColor Yellow
        
        $Root = [ADSI]"LDAP://RootDSE"
        $ConfigurationName = $Root.rootDomainNamingContext
        $scp = New-Object System.DirectoryServices.DirectoryEntry;
        $scp.Path = "LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration," + $ConfigurationName;
        if ($scp.Keywords -ne $null) {
            #Write-Host "Service Connection Point (SCP) is configured as following:" -ForegroundColor Green
        
            $scp.Keywords
        
            #check SCP
            #Write-Host ''
            #Write-Host "Testing Service Connection Point (SCP) configuration..." -ForegroundColor Yellow
        
            $TID = $scp.Keywords | Select-String azureADId
            $TID = ($TID.tostring() -split ":")[1].trim()
            
            $TN = $scp.Keywords | Select-String azureADName
            $TN = ($TN.tostring() -split ":")[1].trim()
            $script:TenantName = $TN

            report "DeviceIdentity.SCPDomainSide.TenantId" $TID $script:checks
            report "DeviceIdentity.SCPDomainSide.TenantName" $TN $script:checks

            #CheckMSOnline
            #Checking tenant name
            #Write-Host ''
            #Write-Host "Testing Tenant Name..." -ForegroundColor Yellow
        
            $InvokeResult = ""
            $InvokeResult = (Invoke-WebRequest -Uri "https://login.microsoftonline.com/$TN/.well-known/openid-configuration" -UseBasicParsing).content | ConvertFrom-Json
            if ($InvokeResult) {
                $TenantID = ($InvokeResult.issuer.tostring() -split "https://sts.windows.net/")[1].trim()
                $TenantID = ($TenantID.tostring() -split "/")[0].trim()
                #Write-Host "Test passed: Tenant Name is configured correctly" -ForegroundColor Green
                #
                #Write-Host ''
                #Write-Host "Testing Tenant ID..." -ForegroundColor Yellow
        
                if ($TenantID -eq $TID) {
                    Write-Host "Test passed: Tenant ID is configured correctly" -ForegroundColor Green
                    report "DeviceIdentity.SCPDomainSide.ConfCheck" "OK" $script:checks
                }
                else {
                    Write-Host "Test failed: Tenant ID is not configured correctly" -ForegroundColor Red
                    report "DeviceIdentity.SCPDomainSide.ConfCheck" "KO" $script:checks
                    report "Error.DeviceIdentity.SCPDomainSide.ConfCheck" "KO" $script:checks
                    #Write-Host ''
                    #Write-Host "Recommended action: Make sure the Tenant ID is configured correctly in SCP." -ForegroundColor Yellow
        
                }

            }
            else {
                Write-Host "Test failed: Tenant Name is not configured correctly" -ForegroundColor Red
                report "DeviceIdentity.SCPDomainSide.ConfCheck" "KO" $script:checks
                report "Error.DeviceIdentity.SCPDomainSide.ConfCheck" "KO" $script:checks
                #Write-Host ''
                #Write-Host "Recommended action: Make sure the Tenant Name is configured correctly in SCP." -ForegroundColor Yellow
  
            }

        }
        else {
            Write-Host "Test failed: Service Connection Point is not configured in your forest" -ForegroundColor red
            report "DeviceIdentity.SCPDomainSide.ConfCheck" "KO" $script:checks
            report "Error.DeviceIdentity.SCP.ConfCheck" "No SCP Configured" $script:checks
            #Write-Host ''
            #Write-Host "Recommended action: make sure to configure SCP in your forest" -ForegroundColor Yellow
 
        }
    }
}

Function checkProxy {
    # Check Proxy settings
    
    $script:ProxyServer = "NoProxy"
    $winHTTP = netsh winhttp show proxy
    $Proxy = $winHTTP | Select-String server
    $script:ProxyServer = $Proxy.ToString().TrimStart("Proxy Server(s) :  ")
    $Bypass = $winHTTP | Select-String Bypass
    if ($null -ne $Bypass) {
        $Bypass = $Bypass.ToString().TrimStart("Bypass List     :  ")
    }

    if ($script:ProxyServer -eq "Direct access (no proxy server).") {
        $script:ProxyServer = "NoProxy"
        
    }

    if ( ($script:ProxyServer -ne "NoProxy") -and (-not($script:ProxyServer.StartsWith("http://")))) {
        $script:ProxyServer = "http://" + $script:ProxyServer
    }

    #CheckwinInet proxy
    $winInet = Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    
    $winInetProxy = "Proxy Server List : " + $winInet.ProxyServer
    
    $winInetBypass = "Proxy Bypass List : " + $winInet.ProxyOverride
    
    $winInetAutoConfigURL = "    AutoConfigURL : " + $winInet.AutoConfigURL
    
                    

    report "Network.Proxy.Proxy" $script:ProxyServer $script:checks
    report "Network.Proxy.ByPass" $Bypass $script:checks
    report "Network.Proxy.WinInetProxy" $winInet.ProxyServer $script:checks
    report "Network.Proxy.winInetBypass" $winInet.ProxyOverride $script:checks
    report "Network.Proxy.winInetAutoConfigURL" $winInet.AutoConfigURL $script:checks
    #$script:checks.Network.Proxy.Add("Proxy",$script:ProxyServer)
    #$script:checks.Network.Proxy.Add("ByPass",$Bypass)
    #$script:checks.Network.Proxy.Add("WinInetProxy",$winInet.ProxyServer)
    #$script:checks.Network.Proxy.Add("winInetBypass",$winInet.ProxyOverride)
    #$script:checks.Network.Proxy.Add("winInetAutoConfigURL",$winInet.AutoConfigURL)
    
}


Function CheckADjoined {

    #Check Scheduled Task for HAADJ
    $TaskState = (Get-ScheduledTask -TaskName Automatic-Device-Join).State
    if (($TaskState -ne 'Ready') -and ($TaskState -ne 'Bereit')) {
        Write-Host "Test failed: Automatic-Device-Join task scheduler is not ready" -ForegroundColor Red
        report "Error.DeviceIdentity.ActiveDirectory.DeviceJoinedTS" "Scheduled Task is not ready" $script:checks
        report "DeviceIdentity.ActiveDirectory.DeviceJoinedTS" "Scheduled Task is not ready" $script:checks
        #$script:checks.Errors.ActiveDirectory.Add("DeviceJoinedTS", "Scheduled Task is not ready")
        #$script:checks.Device.ActiveDirectory.Add("DeviceJoinedTS", "KO")
        #Write-Host "Recommended action: please enable 'Automatic-Device-Join' task from 'Task Scheduler Library\Microsoft\Windows\Workplace Join'." -ForegroundColor Yellow
    }
    else {
        Write-Host "Test passed: Automatic-Device-Join task scheduler is ready" -ForegroundColor Green
        #$script:checks.Device.ActiveDirectory.Add("DeviceJoinedTS", "OK")
        report "DeviceIdentity.ActiveDirectory.DeviceJoinedTS" "OK" $script:checks
    }

    #Check SCP configuration
    VerifySCP

    # Test DC connectivity
    Write-Host ''
    Write-Host "Testing Domain Controller connectivity..." -ForegroundColor Yellow
   
    $DCName = ""
    $DCTest = nltest /dsgetdc:
    $DCName = $DCTest | Select-String DC | Select-Object -first 1
    $DCName = ($DCName.tostring() -split "DC: \\")[1].trim()
    if (($DCName.length) -eq 0) {
        Write-Host "Test failed: connection to Domain Controller failed" -ForegroundColor Red
        report "Error.DeviceIdentity.ActiveDirectory.DSGETDC" "KO" $script:checks
        report "DeviceIdentity.ActiveDirectory.DSGETDC" "Failed" $script:checks
        #$script:checks.Errors.ActiveDirectory.Add("DCConnectivity", "Failed")
        #$script:checks.Device.ActiveDirectory.Add("DCConnectivity", "KO")
        #Write-Host ''
        #Write-Host "Recommended action: Make sure that the device has a line of sight connection to the Domain controller" -ForegroundColor Yellow
    }
    else {
        Write-Host "Test passed: connection to Domain Controller succeeded" -ForegroundColor Green
        report "DeviceIdentity.ActiveDirectory.DSGETDC" $DCName $script:checks
        #$script:checks.Device.ActiveDirectory.Add("DCConnectivity", "OK")
 
    }

    ###conn

    #Testing if the device synced (with managed domain)
    #Write-Host ''
    #Write-Host "Checking domain authentication type..." -ForegroundColor Yellow
 
    #Check if URL status code is 200
    #check through proxy if exist
    #run under sys account
    if ($null -eq $script:TenantName) {
        Write-Host "Don't know the tenant name. Exiting" -ForegroundColor Red
        report "Error.DeviceIdentity.TenantName" "Missing" $script:checks
        return
    }

    $UserRealmJson = ""
    $UserRelmURL = "https://login.microsoftonline.com/common/UserRealm/?user=" + ($script:TenantName) + "&api-version=1.0"
    if (($script:ProxyServer -eq "NoProxy") -or ($script:ProxyServer -eq "winInet")) {
        $UserRealmJson = Invoke-WebRequest -uri $UserRelmURL -UseBasicParsing
        #$UserRealmJson = RunPScript -PSScript $PSScript #| Out-Null
    }
    else {
        $UserRealmJson = Invoke-WebRequest -uri $UserRelmURL -UseBasicParsing -Proxy $script:ProxyServer
        #$UserRealmJson = RunPScript -PSScript $PSScript #| Out-Null
    }
    #Test failed with both winHTTP & winInet
    if (!($UserRealmJson)) {
        Write-Host "Test failed: Could not check domain authentication type." -ForegroundColor Red
        report "Error.DeviceIdentity.ActiveDirectory.ADAuthType" "KO" $script:checks
        report "DeviceIdentity.ActiveDirectory.ADAuthType" "KO" $script:checks
        #$script:checks.Errors.ActiveDirectory.Add("ADAuthType", "Failed")
        #$script:checks.Device.ActiveDirectory.Add("ADAuthType", "KO")
        #Write-Host ''
        #Write-Host "Recommended action: Make sure the device has Internet connectivity." -ForegroundColor Yellow
        return
    }
    

    $UserRealm = $UserRealmJson.Content | ConvertFrom-Json
    $script:UserRealmMEX = $UserRealm.federation_metadata_url
    $script:FedProtocol = $UserRealm.federation_protocol
    #Check if the domain is Managed
    if ($UserRealm.account_type -eq "Managed") {
        #The domain is Managed
        Write-Host "The configured domain is Managed" -ForegroundColor Green
        report "DeviceIdentity.ActiveDirectory.ADAuthType" "Managed" $script:checks
        #$script:checks.Device.ActiveDirectory.Add("ADAuthType", "Managed")
        SyncJoinCheck

    }
    else {
        #The domain is federated
        Write-Host "The configured domain is Federated" -ForegroundColor Green
        #$script:checks.Device.ActiveDirectory.Add("ADAuthType", "Federated")
        report "DeviceIdentity.ActiveDirectory.ADAuthType" "Federated" $script:checks
        #Testing Federation protocol
        #Write-Host ''
        #Write-Host "Testing WSTrust Protocol..." -ForegroundColor Yellow
        
        if ($script:FedProtocol -ne "WSTrust") {
            #Not WSTrust
            Write-Host "Test failed: WFTrust protocol is not enabled on federation service configuration." -ForegroundColor Red
            #$script:checks.Errors.ActiveDirectory.Add("WSTrust", "Failed")
            #$script:checks.Device.ActiveDirectory.Add("WSTrust", "KO")
            report "Warning.DeviceIdentity.ActiveDirectory.WSTrust" "KO" $script:checks
            report "DeviceIdentity.ActiveDirectory.WSTrust" "NotEnabled" $script:checks


            #Write-Host ''
            #Write-Host "Recommended action: Make sure that your federation service supports WSTrust protocol, and WSTrust is enabled on Azure AD federated domain configuration." -ForegroundColor Yellow
            #Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow

            SyncJoinCheck $true
        }
        else {
            #WSTrust enabled
            Write-Host "Test passed: WSTrust protocol is enabled on federation service configuration." -ForegroundColor Green
            #$script:checks.Device.ActiveDirectory.Add("WSTrust", "OK")
            report "Warning.DeviceIdentity.ActiveDirectory.WSTrust" "OK" $script:checks
            #Testing MEX URL
            Write-Host ''
            Write-Host "Testing Metadata Exchange URI (MEX) URL..." -ForegroundColor Yellow

            $ErrorActionPreference = "SilentlyContinue"
            $WebResponse = ""

            #Check if FSName bypassed by proxy
            $ADFSName = $script:UserRealmMEX -Split "https://"
            $ADFSName = $ADFSName[1] -Split "/"
            $FSName = $ADFSName[0]
            $ADFSName = $FSName -split "\."
            $ADFSName[0], $ADFSNameRest = $ADFSName
            $ADFSNameAll = $ADFSNameRest -join '.'
            $ADFSNameAll = "*." + $ADFSNameAll
            $script:FedProxy = $script:Bypass.Contains($FSName) -or $script:Bypass.Contains($ADFSNameAll)

            #If there is no proxy, or FSName bypassed by proxy
            if ((($script:ProxyServer -eq "NoProxy") -or ($script:ProxyServer -eq "winInet")) -or ($script:FedProxy)) {
                $WebResponse = Invoke-WebRequest -uri $script:UserRealmMEX -UseBasicParsing
                #$WebResponse = RunPScript -PSScript $PSScript
            }
            else {
                $WebResponse = Invoke-WebRequest -uri $script:UserRealmMEX -UseBasicParsing -Proxy $script:ProxyServer
                #$WebResponse = RunPScript -PSScript $PSScript
            }

            if ((($WebResponse.Content).count) -eq 0 ) {
                #Not accessible
                Write-Host "Test failed: MEX URL is not accessible." -ForegroundColor Red
                #$script:checks.Errors.ActiveDirectory.Add("MEXURL", "Failed")
                #$script:checks.Device.ActiveDirectory.Add("MEXURL", "KO")
                report "Warning.DeviceIdentity.ActiveDirectory.MEXURL" "KO" $script:checks
                report "DeviceIdentity.ActiveDirectory.MEXURL" "KO" $script:checks
                #Write-Host ''
                #Write-Host "Recommended action: Make sure the MEX URL $script:UserRealmMEX is accessible." -ForegroundColor Yellow
                #Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow

                SyncJoinCheck $true
            }
            else {
                #MEX is accessible
                Write-Host "Test passed: MEX URL '$script:UserRealmMEX' is accessible." -ForegroundColor Green
                #$script:checks.Device.ActiveDirectory.Add("MEXURL", "OK")
                report "DeviceIdentity.ActiveDirectory.MEXURL" "OK" $script:checks

                #Write-Host "Testing windowstransport endpoints on your federation service..." -ForegroundColor Yellow
                
                $WebResponseXMLContent = [xml]$WebResponse.Content 
                foreach ($Object in $WebResponseXMLContent.definitions.service.port) {
                    if ($Object.EndpointReference.Identity.xmlns -eq "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity") {
                        $WTransportURL = $Object.EndpointReference.Address
                    }
                }
                if ($WTransportURL) {
                    #Write-Host "Test passed: windowstransport endpoint is enabled on your federation service as the following:" -ForegroundColor Green
                    #$WTransportURL
                
                    #Testing if the federation service is ADFS:
                    if ($WTransportURL.contains('/adfs/')) {
                        # Federation service is ADFS
                        ''
                        #Write-Host "Testing device authentication against your federation service..." -ForegroundColor Yellow
 
                        if ($WTransportURL.contains('/2005/')) {
                            $Envelope = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wssc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust"><s:Header><wsa:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action><wsa:To s:mustUnderstand="1">' + $WTransportURL + '</wsa:To><wsa:MessageID>urn:uuid:65925CF8-DE9C-43DA-B193-66575B649631</wsa:MessageID></s:Header><s:Body><wst:RequestSecurityToken Id="RST0"><wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>urn:federation:MicrosoftOnline</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType></wst:RequestSecurityToken></s:Body></s:Envelope>'
                        }
                        elseif ($WTransportURL.contains('/13/')) {
                            $Envelope = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><s:Header><a:Action s:mustUnderstand="1">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action><a:MessageID>urn:uuid:DD679E17-7902-4EEA-AA45-071CFFE27502</a:MessageID><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand="1">' + $WTransportURL + '</a:To></s:Header><s:Body><trust:RequestSecurityToken xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><a:EndpointReference><a:Address>urn:federation:MicrosoftOnline</a:Address></a:EndpointReference></wsp:AppliesTo><trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType><trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType></trust:RequestSecurityToken></s:Body></s:Envelope>'
                        }
                        $Body = [String]::Format($Envelope, $WTransportURL, "urn:federation:MicrosoftOnline")
                        #If there is no proxy, or FSName bypassed by proxy
                        if ((($script:ProxyServer -eq "NoProxy") -or ($script:ProxyServer -eq "winInet")) -or ($script:FedProxy)) {
                            $webresp = Invoke-WebRequest $WTransportURL -Method Post -Body $Body -ContentType 'application/soap+xml; charset=utf-8' -UseDefaultCredentials -UseBasicParsing
                            #$webresp = RunPScript -PSScript $PSScript
                        }
                        else {
                            $webresp = Invoke-WebRequest $WTransportURL -Method Post -Body $Body -ContentType 'application/soap+xml; charset=utf-8' -UseDefaultCredentials -UseBasicParsing -Proxy $script:ProxyServer
                            #$webresp = RunPScript -PSScript $PSScript
                        }
                        $tokenXml = [xml]$webresp.Content
                        $Token = $tokenXml.OuterXml
                        if ($Token.Contains("FailedAuthentication")) {
                            Write-Host "Test failed: Device authentication failed against your federation service" -ForegroundColor Red
                            #$script:checks.Errors.ActiveDirectory.Add("ADFSDeviceAuth", "Failed")
                            #$script:checks.Device.ActiveDirectory.Add("ADFSDeviceAuth", "KO")
                            report "DeviceIdentity.ActiveDirectory.ADFSDeviceAuth" "KO" $script:checks
                            report "Warning.DeviceIdentity.ActiveDirectory.ADFSDeviceAuth" "KO" $script:checks


                            #Write-Host ''
                            #Write-Host "Recommended action: Make sure that your federation service allows non-interactive/device authenticaion." -ForegroundColor Yellow
                            #Write-Host "Important Note: if you force MFA, make sure to exclude it for non-interactive/device authenticaion." -ForegroundColor Yellow
                            #Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
 
                            SyncJoinCheck $true
                        }
                        else {
                            Write-Host "Test passed: Device authenticated successfully." -ForegroundColor Green
                            report "DeviceIdentity.ActiveDirectory.ADFSDeviceAuth" "OK" $script:checks
                            Write-Host "Testing Device registration claim rules..." -ForegroundColor Yellow
         
                            $fedjoinfailed = $false
                            if ($Token.Contains("primarysid")) {
                                Write-Host "Test passed: 'primarysid' claim is configured." -ForegroundColor Green
                                report "DeviceIdentity.ActiveDirectory.PrimarySID" "OK" $script:checks
                            }
                            else {
                                Write-Host "Test failed: 'primarysid' claim is NOT configured." -ForegroundColor Red
                                report "DeviceIdentity.ActiveDirectory.PrimarySID" "KO" $script:checks
                                $fedjoinfailed = $true
                            }
                            if ($Token.Contains("accounttype")) {
                                Write-Host "Test passed: 'accounttype' claim is configured." -ForegroundColor Green
                                report "DeviceIdentity.ActiveDirectory.AccountType" "OK" $script:checks
                            }
                            else {
                                Write-Host "Test failed: 'accounttype' claim is NOT configured." -ForegroundColor Red
                                report "DeviceIdentity.ActiveDirectory.AccountType" "OK" $script:checks
                                $fedjoinfailed = $true
                            }
                            if ($Token.Contains("ImmutableID")) {
                                Write-Host "Test passed: 'ImmutableID' claim is configured." -ForegroundColor Green
                                report "DeviceIdentity.ActiveDirectory.ImmutableID" "OK" $script:checks
                            }
                            else {
                                Write-Host "Test failed: 'ImmutableID' claim is NOT configured." -ForegroundColor Red
                                report "DeviceIdentity.ActiveDirectory.ImmutableID" "OK" $script:checks
                                $fedjoinfailed = $true
                            }
                            if ($Token.Contains("onpremobjectguid")) {
                                Write-Host "Test passed: 'onpremobjectguid' claim is configured." -ForegroundColor Green
                                report "DeviceIdentity.ActiveDirectory.onpremobjectguid" "OK" $script:checks
                            }
                            else {
                                Write-Host "Test failed: 'onpremobjectguid' claim is NOT configured." -ForegroundColor Red
                                report "DeviceIdentity.ActiveDirectory.onpremobjectguid" "OK" $script:checks
                                $fedjoinfailed = $true
                            }

                            if ($fedjoinfailed) {
                                ''
                                report "Warning.DeviceIdentity.ActiveDirectory.DeviceRegistrationADFS" "KO" $script:checks
                                report "DeviceIdentity.ActiveDirectory.DeviceRegistrationADFS" "KO" $script:checks
                                #Write-Host "Test failed: Device registration claim rules are NOT configured correctly." -ForegroundColor Red
                                #Write-Host "Recommended action: Make sure that claim rules are configured on 'Microsoft Office 365' Relying Part Trust. For more info, see https://docs.microsoft.com/en-us/azure/active-directory/devices/hybrid-azuread-join-manual" -ForegroundColor Yellow
                                #Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
                                SyncJoinCheck $true
                            }
                            else {
                                ''
                                Write-Host "Test passed: Device registration claim rules are configured correctly." -ForegroundColor Green
                                report "DeviceIdentity.ActiveDirectory.DeviceRegistrationADFS" "OK" $script:checks

           
                            }

                        }
                    }

                }
                else {
                    Write-Host "Test failed: windowstransport endpoints are disabled on your federation service" -ForegroundColor Red
                    report "Warning.DeviceIdentity.ActiveDirectory.ADFSwindowsTransportEndpoint" "KO" $script:checks
                    report "DeviceIdentity.ActiveDirectory.ADFSwindowsTransportEndpoint" "KO" $script:checks

                    #Write-Host ''
                    #Write-Host "Recommended action: Make sure that windowstransport endpoints are enabled on your federation service." -ForegroundColor Yellow
                    #Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
        
                    SyncJoinCheck $true
                }

                ###
            }

        }

    }   

}

Function Get-DsRegStatus () {

    if ($null -eq $script:dsregcmd) {

        if (test-path -path $env:windir\system32\dsregcmd.exe) {

            $dsregcmd = &dsregcmd /status
		
            # Dump dsregcmd info to results
            $dsregcmd  | Out-File ".\dsregcmd.txt"
	
            $o = New-Object -TypeName PSObject
            foreach ($line in $dsregcmd) {
                if ($line -like "| *") {
                    if (-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so) {
                        Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
                    }
                    $currentSection = $line.Replace("|", "").Replace(" ", "").Trim()
                    $so = New-Object -TypeName PSObject
                }
                elseif ($line -match " *[A-z]+ : [A-z0-9\{\}]+ *") {
                    Add-Member -InputObject $so -MemberType NoteProperty -Name (([String]$line).Trim() -split " : ")[0] -Value (([String]$line).Trim() -split " : ")[1] -ErrorAction SilentlyContinue
                }
            }
            if (-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so) {
                Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
            }
            $script:dsregcmd = $o
            return $o
        }
    }
    else {
        return $script:dsregcmd
    }

    return $null
}

Function AnalyzeClientAnalyzer($path) {
    $xmlresult = [XML](get-content $path)
    


    ## Check if network prereq are ok
    if ( (($xmlresult.MDEresults.events.event | where category -eq "Connectivity").severity -contains "Error") -or (($xmlresult.MDEresults.events.event | where category -eq "Connectivity").severity -contains "Warning")) {
        Write-Error "It seems that there's network issue, please confirm by looking at the MDEClientAnalyzer results"
        foreach ($test in ($xmlresult.MDEresults.events.event | where category -eq "Connectivity")) {
            report ("Network.Connectivity." + $test.check + ".Severity") $test.Severity $script:checks
            report ("Network.Connectivity." + $test.check + ".CheckResult") $test.checkresult $script:checks
            report ("Network.Connectivity." + $test.check + ".Guidance") $test.Guidance $script:checks
        }
        #report "Network.Connectivity" "Error" $script:checks

        report "Network.WinHTTPProxy" $xmlresult.MDEResults.general.SystemWideProxy.value $script:checks
        report "Error.Connectivity" "Error" $script:checks
    }
    else {
        report "Network.Connectivity" "OK" $script:checks
        report "Network.WinHTTPProxy" $xmlresult.MDEResults.general.SystemWideProxy.value $script:checks
        
    }
    
    
    ## Check device identity
    

    report "DeviceIdentity.DeviceName" $xmlresult.MDEResults.devInfo.deviceName.value $script:checks
    ## While there's a bug in the MDEClientAnalyzer
    $dsreg = Get-DsRegStatus

    if ( ($dsreg.DeviceState.DomainJoined -eq "YES") -and ($dsreg.DeviceState.AzureADJoined -eq "YES")) {
        report "DeviceIdentity.Status" "Hybrid Azure AD joined" $script:checks
                
        CheckADjoined
    }
    elseif ( ($dsreg.DeviceState.DomainJoined -eq "YES")) {
        report "DeviceIdentity.Status" "Domain joined" $script:checks

        
        Write-Output "Additional check needs to be performed"
        CheckADjoined
    }
    elseif ( ($dsreg.DeviceState.AzureADJoined -eq "YES")) {
        report "DeviceIdentity.Status" "Azure AD joined" $script:checks
        
    }
    elseif ( ($dsreg.DeviceState.EnterpriseJoined -eq "YES")) {
        report "DeviceIdentity.Status" "Workplace joined" $script:checks
        
    }
    else {
        report "DeviceIdentity.Status" "Workgroup" $script:checks
        
    }


    <#
    
    
    if ( ($xmlresult.MDEResults.MDEDevConfig.DomainJoined.value -eq "YES") -and ($xmlresult.MDEResults.MDEDevConfig.AzureADJoined.value -eq "YES")) {
        #$script:checks.Device.Add("DeviceIdentity", "Hybrid Azure AD joined")
        #$script:checks.Device.Add("ActiveDirectory", @{})
        #$script:checks.Errors.Add("ActiveDirectory", @{})
        CheckADjoined
    }
    elseif ( ($xmlresult.MDEResults.MDEDevConfig.DomainJoined.value -eq "YES")) {
        #$script:checks.Device.Add("DeviceIdentity", "Domain joined")
        Write-Output "Additional check needs to be performed"
        #$script:checks.Device.Add("ActiveDirectory", @{})
        #$script:checks.Errors.Add("ActiveDirectory", @{})
        CheckADjoined
    }
    elseif ( ($xmlresult.MDEResults.MDEDevConfig.AzureADJoined.value -eq "YES")) {
        #$script:checks.Device.Add("DeviceIdentity", "Azure AD joined")
    }
    elseif ( ($xmlresult.MDEResults.MDEDevConfig.WorkplaceJoined.value -eq "YES")) {
        #$script:checks.Device.Add("DeviceIdentity", "Workplace joined")
    }
    else {
        #$script:checks.Device.Add("DeviceIdentity", "Workgroup")
    }
    #>


    ## Check device management
    
    report "Management.MDMEnrollmentState" $xmlresult.MDEResults.MDEDevConfig.MDMEnrollmentState.value $script:checks
    if ($script:checks.Management.MDMEnrollmentState -eq "MDM enrolled") {
        $currentEnrollmentId = Get-ItemPropertyValue -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Logger" -Name "CurrentEnrollmentId"
        $MDMServiceLocation = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\" + $currentEnrollmentId
        $ProviderID = Get-ItemPropertyValue -Path $MDMServiceLocation -Name "ProviderID"
        report "Management.MDM" $ProviderID $script:checks
    }
    report "Management.SenseCMEnrollmentStatus" $xmlresult.MDEResults.MDEDevConfig.SenseCMEnrollmentStatus.value $script:checks

    TestConfigMgr
    if ($null -ne (select-xml -XPATH "/MDEResults/MDEDevConfig/*/alert[text()!='None']" -Xml $xmlresult).Node.'#text') {
        report "Error.CMEnrollment" (select-xml -XPATH "/MDEResults/MDEDevConfig/*/alert[text()!='None']" -Xml $xmlresult).Node.'#text' $script:checks
    
    }



    ## Check device onboarding in MDE
    
    report "MDE.MDEOnboarded" ($xmlresult.MDEResults.EDRCompInfo.DeviceId.value -ne "") $script:checks
    report "MDE.MDEDeviceID" $xmlresult.MDEResults.EDRCompInfo.DeviceId.value $script:checks
    report "MDE.MDEOrgID" $xmlresult.MDEResults.EDRCompInfo.OrgId.value $script:checks

    
    ## Check MDAV status & configuration
    report "MDAV.MDAVServiceStatus" ($xmlresult.MDEResults.AVCompInfo.DefenderServiceStatus.value) $script:checks
    CheckMDAVConfig

    if ($script:checks.MDAV["MDAVServiceStatus"] -ne "Running") {
        report "Error.MDAV.Service" "NotRunning" $script:checks
    }

    report "MDAV.MDAVState" $xmlresult.MDEResults.AVCompInfo.DefenderState.value $script:checks
    if (!($script:checks.MDAV["MDAVState"] -in ("Active", "Passive", "EDRBlock"))) {
        report "Error.MDAV.MDAVState" "Error" $script:checks
    }
    

    ## Check MD Firewall config
    checkWFConfig
}

Function displayReport {

    $ProdPOCStatus = ""

    #Identity checks
    switch ($script:checks.DeviceIdentity.Status) {
        "Hybrid Azure AD joined" { 
            #if HAADJ + MDM
            #   if MDM = Intune
            #       if SCCM
            #           => HAADJ + Co-management ===> Intune - no change
            #       else
            #           => HAADJ + Intune ===> Intune - no change
            #       break
            #   Endif
            #Endif
            #if MDE Attached
            #    => HAADJ + MDE Attach ===> MDE Attach - no change
            #else
            #    => HAADJ ===> MDE Attach - need to fix MDE Attach config
            
            Write-Report -section "ProductionPOC" -subsection "deviceID" -displayName "Device Identity" -value "Hybrid Azure AD Joined"

            if ($script:checks.Management.MDMEnrollmentState -eq "MDM enrolled") {
                if ($script:checks.Management.MDM -eq "MS DM Server") {
                    $ProdPOCStatus = 1

                    Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "MDE Device Management channel" -value "Intune (MEM)"

                    if ($script:checks.Management.ConfigMgr.Installed -eq "YES") {
                        Write-Host "Easy you are already HAADJ + co-managed" -ForegroundColor Green
                        Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Co-Managed"
                    }
                    else {
                        Write-Host "Easy you are already HAADJ + Intune" -ForegroundColor Green
                        Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Intune (MEM)"
                    }
                    break
                }
                else {

                    Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Third party MDM"
                }
                
            }
            
            Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "MDE Device Management channel" -value "MDE Security Settings Magement (MEM)"

            if ($script:checks.Management.ConfigMgr.Installed -eq "YES") {
                Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Configuration Manager"
            }
            else {
                Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Other"
            }
            

            if ($null -ne $script:checks.Error.CMEnrollment) {
                Write-Host "We need to undestand what's happening with this "+($script:checks.Management.SenseCMEnrollmentStatus) -ForegroundColor Yellow
                $ProdPOCStatus = 2
                Write-Report -section "ProductionPOC" -subsection "comment" -displayName "Comment" -value ("We need to undestand what's happening with this " + $script:checks.Management.SenseCMEnrollmentStatus)
            }
            else {
                    
                Write-Host "Easy you are already HAADJ + MDE Configuration Management is configured" -ForegroundColor Green
                $ProdPOCStatus = 1
            }
                        
            break
        }
        "Domain joined" { 
            #if SCP Domain side is OK OR SCP Client side is OK
            #
            #
            #   if MDM = Intune
            #       if SCCM
            #           => HAADJ + Co-management ===> Intune - no change
            #       else
            #           => HAADJ + Intune ===> Intune - no change
            #       break
            #   Endif
            #Endif
            #if SCP User level is OK
            #    => HAADJ + MDE Attach ===> MDE Attach - no change
            #else
            #    => HAADJ ===> MDE Attach - need to fix MDE Attach config

            Write-Report -section "ProductionPOC" -subsection "deviceID" -displayName "Device Identity" -value "Domain Joined"
            
            #Write-Report -section "ProductionPOC" -subsection "changes" -displayName "Changes" -value "Device will be Hybrid Azure AD Joined, if not possible you should go with a traditional POC"

            if ($script:checks.Management.MDMEnrollmentState -eq "MDM enrolled") {
                if ($script:checks.Management.MDM -eq "MS DM Server") {

                    
                    $ProdPOCStatus = 1
                    Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "MDE Device Management channel" -value "Intune (MEM)"

                    if ($script:checks.Management.ConfigMgr.Installed -eq "YES") {
                        Write-Host "Easy you are already HAADJ + co-managed" -ForegroundColor Green
                        Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Co-Managed"
                    }
                    else {
                        Write-Host "Easy you are already HAADJ + Intune" -ForegroundColor Green
                        Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Intune (MEM)"
                    }
                    break
                }
                else {

                    Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Third party MDM"
                }
            }
            
            $scp = $false

            if ($script:checks.DeviceIdentity.ContainsKey("SCPClientSide")) {
                $scp = ($script:checks.DeviceIdentity.SCPClientSide.ConfCheck -eq "OK")
            }
            if ($script:checks.DeviceIdentity.ContainsKey("SCPDomainSide")) {
                $scp = ($script:checks.DeviceIdentity.SCPClientSide.ConfCheck -eq "OK")
            }

            if (!$scp) {
                Write-Report -section "ProductionPOC" -subsection "HAADJChecks" -displayName "HAADJ prerequisites" -value "SCP is not configured neither client side or domain side"
                Write-Report -section "ProductionPOC" -subsection "changes" -displayName "Changes" -value "You need to configure your domain for Hybrid Azure Active Directory join first"
                Write-Report -section "ProductionPOC" -subsection "comment" -displayName "comment" -value "You can add a client side SCP + enable AAD Connect device sync only for the tests devices. Here is the link to the official doc: https://learn.microsoft.com/en-us/azure/active-directory/devices/howto-hybrid-azure-ad-join"

                $ProdPOCStatus = 5
                
            }

            Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "MDE Device Management channel" -value "MDE Security Settings Magement (MEM)"

            if ($script:checks.Management.ConfigMgr.Installed -eq "YES") {
                Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Configuration Manager"
            }
            else {
                Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Other"
            }
            

            if ($null -ne $script:checks.Error.CMEnrollment) {
                Write-Host "We need to undestand what's happening with this "+($script:checks.Management.SenseCMEnrollmentStatus) -ForegroundColor Yellow
                $ProdPOCStatus = 3  
                Write-Report -section "ProductionPOC" -subsection "comment" -displayName "Comment" -value ("We need to undestand what's happening with this " + $script:checks.Management.SenseCMEnrollmentStatus)
            }
            else {
                    
                Write-Host "Easy you are already HAADJ + MDE Configuration Management is configured" -ForegroundColor Green
                $ProdPOCStatus = 2
                
            }
                        
            break
            
        }
        "Azure AD joined" { 
            
            Write-Report -section "ProductionPOC" -subsection "deviceID" -displayName "Device Identity" -value "Azure AD Joined"

            if ($script:checks.Management.MDMEnrollmentState -eq "MDM enrolled") {
                if ($script:checks.Management.MDM -eq "MS DM Server") {
                    
                    Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "MDE Device Management channel" -value "Intune (MEM)"
                    $ProdPOCStatus = 1
                    
                    if ($script:checks.Management.ConfigMgr.Installed -eq "YES") {

                        Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Co-Managed"
                    }
                    else {

                        Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Intune (MEM)"
                    }
                    break
                }
                else {

                    Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Third party MDM"
                }
                
            }
            
            Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "MDE Device Management channel" -value "MDE Security Settings Magement (MEM)"

            if ($script:checks.Management.ConfigMgr.Installed -eq "YES") {
                Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Configuration Manager"
            }
            else {
                Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Other"
            }
            

            if ($null -ne $script:checks.Error.CMEnrollment) {
                Write-Host "We need to undestand what's happening with this "+($script:checks.Management.SenseCMEnrollmentStatus) -ForegroundColor Yellow
                $ProdPOCStatus = 2       
                Write-Report -section "ProductionPOC" -subsection "comment" -displayName "Comment" -value ("We need to undestand what's happening with this " + $script:checks.Management.SenseCMEnrollmentStatus)
            }
            else {
                    

                $ProdPOCStatus = 1
                Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "MDE Device Management channel" -value "MDE Security Settings Magement (MEM)"
            }
            break 
        }
        "Workplace joined" { break }
        "Workgroup" { 
            Write-Report -section "ProductionPOC" -subsection "deviceID" -displayName "Device Identity" -value "Workgroup"
            Write-Report -section "ProductionPOC" -subsection "changes" -displayName "Changes" -value "Device will be Azure AD Joined"
            $ProdPOCStatus = 1

            #If intune or MDM ok we can stop here
            if ($script:checks.Management.MDMEnrollmentState -eq "MDM enrolled") {
                if ($script:checks.Management.MDMEnrollmentState -eq "MS DM Server") {
                    Write-Host "Easy you are already managed by Intune" -ForegroundColor Green
                    Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Intune (MEM)"
                    Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "MDE Device Management channel" -value "Intune (MEM)"
                }
                else {
                    Write-Host "Easy, we will be using MDE Configuration Management" -ForegroundColor Green
                    Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Third party MDM"
                    Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "MDE Device Management channel" -value "MDE Security Settings Magement (MEM)"
                }
                break
            }
            
            Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "MDE Device Management channel" -value "MDE Security Settings Magement (MEM)"

            if ($script:checks.Management.ConfigMgr.Installed -eq "YES") {
                Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Configuration Manager"
            }
            else {
                Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "Actual Device Management channel" -value "Other"
            }
            

            if ($null -ne $script:checks.Error.CMEnrollment) {
                Write-Host "We need to undestand what's happening with this "+($script:checks.Management.SenseCMEnrollmentStatus) -ForegroundColor Yellow
                $ProdPOCStatus = 2      
                Write-Report -section "ProductionPOC" -subsection "comment" -displayName "Comment" -value ("We need to undestand what's happening with this " + $script:checks.Management.SenseCMEnrollmentStatus)
            }
            else {
                    
                Write-Host "Easy you are already HAADJ + MDE Configuration Management is configured" -ForegroundColor Green
                #Write-Report -section "ProductionPOC" -subsection "deviceMgmt" -displayName "MDE Device Management channel" -value "MDE Security Settings Magement (MEM)"
            }
        }
        default: {
            Write-Host "You should not be here" -ForegroundColor Yellow
        }
    }

    #AV checks
    if ($script:checks.MDE.MDEOnboarded) {
        if ($script:checks.MDAV.MDAVServiceStatus -ne "Running") {
            $ProdPOCStatus = 5
            $comment = "MDAV service is not running"
            Write-Report -section "ProductionPOC" -subsection "comment" -displayName "Comment" -value $comment
        }

    }
    
    if ($script:checks.contains("Error")) {
        if ($script:checks.Error.contains("MDAV") ) {
            $cpt = 0
            foreach ($err in $script:checks.Error.MDAV.Keys) {
                if ($err -like "Disable*") { $cpt++ }
            }

            if ( $cpt -ne 0) {
                $ProdPOCStatus = 5
                $comment = "AV is disabled by registry"
                Write-Report -section "ProductionPOC" -subsection "comment" -displayName "Comment" -value $comment
            }
            else {
                $ProdPOCStatus = 3
            }
        }
    }

    if ($script:checks.MDAV.MDAVState -eq "Passive" ) {
        
        $ProdPOCStatus = 5
        $comment = "Uninstall or disable the third party AV"
        Write-Report -section "ProductionPOC" -subsection "comment" -displayName "Comment" -value $comment
        
    }

    #Check 3rd party AV & FW
    foreach ($i in $script:checks.MDAV.WindowsSecurityCenter.Keys) {
        if ($i -like "AV-*") {
            if ($script:checks.MDAV.WindowsSecurityCenter[$i].State -eq "0") {
                Write-Report -section "AVDetailsInfo" -subsection "activeAV" -displayName "Enabled AV" -value ($script:checks.MDAV.WindowsSecurityCenter[$i].Name)
            }
        }
        elseif ($i -like "FW-*") {
            if ($script:checks.MDAV.WindowsSecurityCenter[$i].State -eq "0") {
                #State =0 means this is active
                Write-Report -section "AVDetailsInfo" -subsection "thirdpartyFW" -displayName "Enabled FW" -value ($script:checks.MDAV.WindowsSecurityCenter[$i].Name)
            }
        }
    }

    #Display MDAV config
    Write-Report -section "AVDetailsInfo" -subsection "RealtimeMonitoring" -displayName "Realtime monitoring" -value $script:checks.MDAV.Config.RealtimeMonitoring
    Write-Report -section "AVDetailsInfo" -subsection "BehaviorMonitoring" -displayName "Behavior monitoring" -value $script:checks.MDAV.Config.BehaviorMonitoring
    Write-Report -section "AVDetailsInfo" -subsection "MAPS" -displayName "MAPS configuration" -value $script:checks.MDAV.Config.MAPSReporting


    #KB missing patches
    if ($script:checks.OS.contains("Patches")) {
        foreach ($i in $script:checks.OS.Patches.Keys) {
            if ($script:checks.OS.Patches[$i].Status -eq "Missing") {
                $ProdPOCStatus = 5
                $comment = ("Patch $i is missing")
                Write-Report -section "ProductionPOC" -subsection "Patches" -displayName "Missing Patches" -value $comment
            }
        }
    }

    #third party FW
    #MDFW need to check our firewall (service status, profile configuration)
    
    Write-Report -section "FWDetailsInfo" -subsection "DomainEnabled" -displayName "Domain profile Enabled" -value $script:checks.MDFW.Profiles.Domain.Enabled
    Write-Report -section "FWDetailsInfo" -subsection "DomainInboundAction" -displayName "Domain profile Inbound Action" -value $script:checks.MDFW.Profiles.Domain.DefaultInboundAction
    Write-Report -section "FWDetailsInfo" -subsection "DefaultOutboundAction" -displayName "Domain profile Outbound Action" -value $script:checks.MDFW.Profiles.Domain.DefaultOutboundAction
    Write-Report -section "FWDetailsInfo" -subsection "AllowLocalFirewallRules" -displayName "Allow local rules" -value $script:checks.MDFW.Profiles.Domain.AllowLocalFirewallRules

    Write-Report -section "FWDetailsInfo" -subsection "PublicEnabled" -displayName "Public profile Enabled" -value $script:checks.MDFW.Profiles.Public.Enabled
    Write-Report -section "FWDetailsInfo" -subsection "PublicInboundAction" -displayName "Public profile Inbound Action" -value $script:checks.MDFW.Profiles.Public.DefaultInboundAction
    Write-Report -section "FWDetailsInfo" -subsection "DefaultOutboundAction" -displayName "Public profile Outbound Action" -value $script:checks.MDFW.Profiles.Public.DefaultOutboundAction
    Write-Report -section "FWDetailsInfo" -subsection "AllowLocalFirewallRules" -displayName "Allow local rules" -value $script:checks.MDFW.Profiles.Public.AllowLocalFirewallRules

    Write-Report -section "FWDetailsInfo" -subsection "PrivateEnabled" -displayName "Private profile Enabled" -value $script:checks.MDFW.Profiles.Private.Enabled
    Write-Report -section "FWDetailsInfo" -subsection "PrivateInboundAction" -displayName "Private profile Inbound Action" -value $script:checks.MDFW.Profiles.Private.DefaultInboundAction
    Write-Report -section "FWDetailsInfo" -subsection "DefaultOutboundAction" -displayName "Private profile Outbound Action" -value $script:checks.MDFW.Profiles.Private.DefaultOutboundAction
    Write-Report -section "FWDetailsInfo" -subsection "AllowLocalFirewallRules" -displayName "Allow local rules" -value $script:checks.MDFW.Profiles.Private.AllowLocalFirewallRules

    Write-Report -section "FWDetailsInfo" -subsection "Packet" -displayName "Audit Packets" -value $script:checks.MDFW.Auditing.Packet.Audit
    Write-Report -section "FWDetailsInfo" -subsection "Connection" -displayName "Audit Connection" -value $script:checks.MDFW.Auditing.Connection.Audit
    

    #Other MDE auditing
    checkAdvAuditConfig
    Write-Report -section "MDEDevConfig" -subsection "UserMgmtAudit" -displayName "Audit User Account Management" -value $script:checks.MDE.Auditing.UserMgmt.Audit
    Write-Report -section "MDEDevConfig" -subsection "GroupMgmtAudit" -displayName "Audit Security Group Management" -value $script:checks.MDE.Auditing.GroupMgmt.Audit
    Write-Report -section "MDEDevConfig" -subsection "SecSystemExtentionAudit" -displayName "Audit Security System Extension" -value $script:checks.MDE.Auditing.SecSystemExtention.Audit

    switch ($ProdPOCStatus) {
        1 { Write-Report -section "ProductionPOC" -subsection "status" -displayName "Production POC Status" -value "OK"  -alert "None"; break }
        2 { Write-Report -section "ProductionPOC" -subsection "status" -displayName "Production POC Status" -value "Should be OK" -alert "Medium"; break }
        5 { Write-Report -section "ProductionPOC" -subsection "status" -displayName "Production POC Status" -value "Change required" -alert "High"; break }
        3 { Write-Report -section "ProductionPOC" -subsection "status" -displayName "Production POC Status" -value "Manual analysis needed" -alert "Medium"; break }
    }
}

Function checkWFConfig {
    $firewallconfig = Get-NetFirewallProfile

    foreach ($i in $firewallconfig) {
        report ("MDFW.Profiles."+$i.Name+".Enabled") $i.Enabled $script:checks
        report ("MDFW.Profiles."+$i.Name+".DefaultInboundAction") $i.DefaultInboundAction $script:checks
        report ("MDFW.Profiles."+$i.Name+".DefaultOutboundAction") $i.DefaultOutboundAction $script:checks
        report ("MDFW.Profiles."+$i.Name+".AllowLocalFirewallRules") $i.AllowLocalFirewallRules $script:checks
    }

    $categories = "Filtering Platform Packet Drop,Filtering Platform Connection"
    $current = auditpol /get /subcategory:"$($categories)" /r | ConvertFrom-Csv
    report "MDFW.Auditing.Packet.Audit" ( ($current | where Subcategory -eq "Filtering Platform Packet Drop").'Inclusion Setting') $script:checks
    report "MDFW.Auditing.Connection.Audit" ( ($current | where Subcategory -eq "Filtering Platform Connection").'Inclusion Setting') $script:checks
}    

Function checkAdvAuditConfig {
    $categories = "User Account Management,Security Group Management,Security System Extension"
    $current = auditpol /get /subcategory:"$($categories)" /r | ConvertFrom-Csv

    report "MDE.Auditing.UserMgmt.Audit" ( ($current | where Subcategory -eq "User Account Management").'Inclusion Setting') $script:checks
    report "MDE.Auditing.GroupMgmt.Audit" ( ($current | where Subcategory -eq "Security Group Management").'Inclusion Setting') $script:checks
    report "MDE.Auditing.SecSystemExtention.Audit" ( ($current | where Subcategory -eq "Security System Extension").'Inclusion Setting') $script:checks
}

Function checkOS {

    #Getting OS Version info
    $OSInfo = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion"
    #report "OS.SKU.Name" $OSinfo.EditionID $script:checks
    #report "OS.DisplayVersion" $OSInfo.DisplayVersion $script:checks
    #report "OS.ProductName" $OSInfo.ProductName $script:checks
    #report "OS.BuidNumber" ([environment]::OSVersion.Version.tostring()) $script:checks
    #
    #Checking for missing patches
    $sku = (get-wmiobject win32_operatingsystem).OperatingSystemSKU
    report "OS.SKU.ID" $sku $script:checks
    $kbToCheck = @{}
    if ($OSInfo.ProductName -like "*Server*") {
        #Server SKU
        #Windows 2022
        $kbToCheck.Add("10.0.20348", @{"KB5006745" = "October 19, 2021" })

        #Windows 2019
        $kbToCheck.Add("10.0.17763", @{"KB5006744" = "October 19, 2021" })

        #Windows 2016
        $kbToCheck.Add("10.0.14393", @{"KB5005942" = "Servicing Stack September 2021";
                "KB4457127"                        = "Cumulative update September 2018"
            })
        
        #Windows 2012R2
        $kbToCheck.Add("6.3.9600", @{"KB2999226" = "Update for Universal C Runtime";
                "KB3080149"                      = "Update for customer experience and diagnostic telemetry";
                "KB3045999"                      = "Security Update for Windows Server 2012 R2"
            })
    }
    else {
        #client SKU

        #Windows 11
        $kbToCheck.Add("10.0.22000", @{})

        #Windows 10
        $kbToCheck.Add("10.0.16299", @{"KB5006738" = "October 26, 2021" })
        


    }

    $osVersion = [environment]::OSVersion.Version.Major.tostring() + "." + [environment]::OSVersion.Version.Minor.tostring()
    $osBuild = [environment]::OSVersion.Version.Build.tostring()


    foreach ($os in $kbToCheck.Keys) {
        
        $os -match "^([0-9]+\.[0-9]+)\.([0-9]+)$" | out-null

        if ($osVersion -like $matches[1] -and $osBuild -ge $matches[2]) {

            foreach ($kb in $kbToCheck[$os].Keys) {
                report ("OS.Patches." + $kb + ".Description") $kbToCheck[$os][$kb] $script:checks
                $ErrorActionPreference = 'silentlycontinue' 
                if ($null -eq (get-hotfix -Id $kb)) {
                    report ("OS.Patches." + $kb + ".Status") "Missing" $script:checks
                }
                else {
                    report ("OS.Patches." + $kb + ".Status") "OK" $script:checks
                }
                $ErrorActionPreference = 'continue'
            }
            break
        }
    }

    #Check OS Role installed for servers
    if ($OSInfo.ProductName -like "*Server*") {
        $roles = Get-WindowsFeature | where InstallState -eq "Installed"

        foreach ($r in $roles) {
            report ("OS.RoleFeature." + $r.Name + ".Status") "Installed" $script:checks
            if ($r.Name -eq "AD-Domain-Services") {
                report "Error.OS.RoleFeature" "This is a DC" $script:checks
            }
        }
    }
}

Function collectOutputs {
    
    $compress = @{
        Path             = ($script:LogPath)
        CompressionLevel = "Fastest"
        DestinationPath  = ($script:LogPath + "\..\ProdPOCCheckResults.zip")
    }

    Compress-Archive @compress
}


function Process-XSLT {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$XmlPath, 
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$XslPath,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$HtmlOutput )

    Try {
        if(!(Test-path($XslPath)))
        {
            $url = "https://raw.githubusercontent.com/AntoineJo/Defender365Pilots/master/MDE/MDEReport.xslt"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest $url -UseBasicParsing -OutFile $XslPath
        }


        If ((Test-path($XmlPath)) -and (Test-path($XslPath))) {
            $myXslCompiledTransfrom = new-object System.Xml.Xsl.XslCompiledTransform
            $xsltArgList = New-Object System.Xml.Xsl.XsltArgumentList

            $myXslCompiledTransfrom.Load($XslPath)
            $xmlWriter = [System.Xml.XmlWriter]::Create($HtmlOutput)
		
            $myXslCompiledTransfrom.Transform($XmlPath, $xsltArgList, $xmlWriter)
	
            $xmlWriter.Flush()
            $xmlWriter.Close()

            return $True
        } 
        else {
            Write-Host "Cannot generate html file as one of the input file is missing $XmlPath or $XslPath" -ForegroundColor Yellow
        }
    }
    Catch {
        Write-Host "Cannot generate html file $_" -ForegroundColor Yellow
        return $False
    }
}

cls


      
$script:LogPath = ((Split-Path -parent $PSCommandPath) + "\MDECheckLogs")

$script:MDEAnalizerResultPath 

$ErrorActionPreference = 'silentlycontinue'
Add-Type -AssemblyName System.DirectoryServices.AccountManagement            
$UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current
If ($UserPrincipal.ContextType -ne "Machine") {
    $script:UserUPN = whoami /upn
}
$ErrorActionPreference = 'continue'

if ($false -eq (Test-Path $script:LogPath)) {
    mkdir $script:LogPath | Out-Null
}

$script:checks = @{}


checkProxy

#DSRegToolStart
#DJ++TS

if (!($null -eq $path -or $path -eq "")) {
    if (Test-Path $path) {
        $path = $path
    }
    else {
        $path = ""
    }
}

if ($null -eq $path -or $path -eq "") {
    $ErrorActionPreference = 'Stop'
    $admin = PSasAdmin
    if ($false -eq $admin) {
        Write-Error "You have to run this as admin"
        exit
    }

    $ErrorActionPreference = 'silentlycontinue'
    RunMDEClientAnalyzer
    $path = ($script:MDEAnalizerResultPath + "\SystemInfoLogs\MDEClientAnalyzer.xml")
}
InitXmlLog $path

checkOS

AnalyzeClientAnalyzer $path


$script:checks | ConvertTo-Json -Depth 9 | Out-File ($script:LogPath + "\ProdPOCChecks.json")


displayReport

$script:xmlDoc.Save($script:LogPath + "\output.xml")

if (Test-Path ($script:LogPath + "\output.xml") -ne $true) {
    $script:xmlDoc.Save($script:LogPath + "\output.xml")
}



Process-XSLT ($script:LogPath + "\output.xml") ($script:LogPath + "\..\MDEReport.xslt") ($script:LogPath + "\output.html")

collectOutputs
