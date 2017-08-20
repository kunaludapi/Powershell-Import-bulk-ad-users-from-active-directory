#requires -version 3
<#
.SYNOPSIS
    Create new user account in Active Directory.
.DESCRIPTION
    The New-AdUserAccount cmdlet creates new user accounts on active directory domain controller from CSV file. It asks for parameter valid CSV file path, Optional Active directory domain name and Credential. This cmdlet uses
.PARAMETER Path
    Prompts you for CSV file path. There are 2 alias CSV and File, This is mandetory parameter and require valid path.
.PARAMETER Domain
    This is active directory domain name where you want to connect. 
.PARAMETER Credential
    Popups for active directory username password, supply domain admin user account for authentication.
.INPUTS
    [String]
    [Switch]
.OUTPUTS
    Output is on console directly.
.NOTES
    Version:        1.0
    Author:         Kunal Udapi
    Creation Date:  12 June 2017
    Purpose/Change: Bulk user account creation in Microsoft Active Directory domain from Excel/csv.
    Useful URLs: http://vcloud-lab.com/entries/active-directory/powershell-installing-and-configuring-active-directory-and-dns-server
.EXAMPLE
    PS C:\>New-AdUserAccount -Path C:\temp\employees.csv

    This command create bulk users account in logged in domain from CSV file, It uses default logged in Credentials.
.Example
    PS C:\>New-AdUserAccount -Path C:\temp\employees.csv -Domain vCloud-lab.com -Credential

    Here I have used all the parameters Path with user information, Domain name and Credentials.
.EXAMPLE
    PS C:\>New-AdUserAccount -Path C:\temp\employees.csv -Domain vCloud-lab.com
#>

[CmdletBinding(SupportsShouldProcess=$True,
    ConfirmImpact='Medium',
    HelpURI='http://vcloud-lab.com',
    DefaultParameterSetName='File')]
Param
(
    [parameter(ParameterSetName = 'File', Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [parameter(ParameterSetName = 'Credential', Position=0, Mandatory=$true)]
    [alias('CSV', 'File')]
    [ValidateScript({
        If(Test-Path $_){$true}else{throw "Invalid path given: $_"}
        })]
    [String]$Path,
    [Parameter(ParameterSetName='Credential', Position=1, Mandatory=$True)]
    [alias('ADServer', 'DomainName')]
    [String]$Domain,
    [Parameter(ParameterSetName='Credential')]
    [Switch]$Credential
)
#$Path = 'C:\temp\employees.csv'
if ($Credential.IsPresent -eq $True) {
    $Cred = Get-Credential -Message 'Type domain credentials to connect remote AD' -UserName (WhoAmI)
}
Import-Csv -Path $Path | foreach -Begin {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-host "Missing....Install ActiveDirectory Powershell feature -- RSAT (Remote Server Administration). Cannot Create Accounts" -BackgroundColor DarkRed
        Break
    }

} -Process {
    $UserProp = @{ 
            Name = $_.Name
            SamAccountName = $_.SamAccountName 
            UserPrincipalName = $_.UserPrincipalName 
            GivenName = $_.GivenName 
            DisplayName = $_.DisplayName 
            Surname = $_.Surname 
            AccountPassword = (ConvertTo-SecureString -AsPlainText $_.AccountPassword -Force) 
            Description = $_.Description
            EmployeeID = $_.EmployeeID 
            EmailAddress = $_.EmailAddress
            Path = $_.Path 
            MobilePhone = $_.MobilePhone
            Company = $_.Company
            Office = $_.Office 
            Department =  $_.Department 
            Division = $_.Division 
            Organization = $_.Organization 
            OfficePhone = $_.OfficePhone 
            StreetAddress = $_.StreetAddress
            City = $_.City
            State = $_.State
            Country = $_.Country
            PostalCode = $_.PostalCode
            ProfilePath = $_.ProfilePath
            ErrorAction = 'Stop'
    }
    try {
        $Name = $_.Name
        Write-Host "Processing account $Name" -NoNewline -BackgroundColor Gray
        switch ($PsCmdlet.ParameterSetName) {
            'Credential' {
                if ($Credential.IsPresent -eq $false) {
                    New-ADUser @UserProp -Server $Domain
                }
                else {
                    New-ADUser @UserProp -Server $Domain -Credential $Cred
                }
                Break
            }
            'File' {
                New-ADUser @UserProp; break
            }
        }
            Enable-ADAccount -Identity $_.SamAccountName -ErrorAction Stop
            Set-ADUser -Identity $_.SamAccountName -ChangePasswordAtLogon $True
            Write-Host "....Account $Name successfully created" -BackgroundColor DarkGreen
    }
    catch {
        Write-Host "....Processing $Name failed" -BackgroundColor DarkRed
    }
} -End {}