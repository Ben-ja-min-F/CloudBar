# In case I need it in the future
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId
)


#   scopes:
#   Zone.Read.All                  - read the cloud scopes (zones)
#   RoleManagement.Read.Defender   - read the role assignments and definitions
#   Directory.Read.All             - resolve user/group ids to names

$scopes = @("Zone.Read.All", "RoleManagement.Read.Defender", "Directory.Read.All")
Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome

$ctx = Get-MgContext
Write-Host "Connected as $($ctx.Account)" -ForegroundColor Green
Write-Host ""

# In case you have more than 100 zones
function Get-AllPages {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url
    )

    $results = @()
    $nextUrl = $Url

    while ($nextUrl -ne $null) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUrl
        foreach ($item in $response.value) {
            $results += $item
        }
        $nextUrl = $response.'@odata.nextLink'
    }

    return $results
}

# Collect report line
$exportLines = @()

function Write-ReportLine {
    param(
        [string]$Text = "",
        $ForegroundColor = $null
    )

    if ($ForegroundColor) {
        Write-Host $Text -ForegroundColor $ForegroundColor
    }
    else {
        Write-Host $Text
    }

    $script:exportLines += $Text
}

# Get zones
Write-Host "Getting zones..." -ForegroundColor Cyan
$zones = Get-AllPages -Url "https://graph.microsoft.com/beta/security/zones"
Write-Host "Found $($zones.Count) zones"

# Get environments (Azure subs / AWS accounts / GCP projects / etc.) for each zone
Write-Host "Getting environments..." -ForegroundColor Cyan
$environmentsByZone = @{}
foreach ($zone in $zones) {
    try {
        $url = "https://graph.microsoft.com/beta/security/zones/$($zone.id)/environments"
        $environmentsByZone[$zone.id] = Get-AllPages -Url $url
    }
    catch {
        Write-Warning "Could not fetch environments for zone $($zone.displayName) ($($zone.id))"
        $environmentsByZone[$zone.id] = @()
    }
}

# Get all Defender role assignments

Write-Host "Getting role assignments..." -ForegroundColor Cyan
$assignments = Get-AllPages -Url "https://graph.microsoft.com/beta/roleManagement/defender/roleAssignments"
Write-Host "Found $($assignments.Count) assignments"


$roleDefLookup = @{}

foreach ($assignment in $assignments) {
    $defId = $assignment.roleDefinitionId

    if ($roleDefLookup.ContainsKey($defId)) {
        continue
    }

    try {
        $url = "https://graph.microsoft.com/beta/roleManagement/defender/roleDefinitions/$defId"
        $def = Invoke-MgGraphRequest -Method GET -Uri $url
        $roleDefLookup[$defId] = $def
    } catch {
        Write-Warning "Could not fetch role definition $defId"
        # Put a dummy entry so we don't try again
        $roleDefLookup[$defId] = [pscustomobject]@{
            displayName = "(unknown role)"
            rolePermissions = @()
        }
    }
}


$principalLookup = @{}

foreach ($assignment in $assignments) {
    foreach ($principalId in $assignment.principalIds) {

        if ($principalLookup.ContainsKey($principalId)) {
            continue
        }
        try {
            $url = "https://graph.microsoft.com/v1.0/directoryObjects/$principalId"
            $obj = Invoke-MgGraphRequest -Method GET -Uri $url

            # Get the type. Comes back as "#microsoft.graph.user"
            $type = $obj.'@odata.type' -replace '#microsoft.graph.', ''

            $name = $obj.displayName
            if (-not $name) {
                $name = $obj.userPrincipalName
            }
            if (-not $name) {
                $name = "(unknown)"
            }

            $principalLookup[$principalId] = [pscustomobject]@{
                Id = $principalId
                DisplayName = $name
                Type = $type
            }
        }
        catch {
            $principalLookup[$principalId] = [pscustomobject]@{
                Id = $principalId
                DisplayName = "(could not resolve)"
                Type = "unknown"
            }
        }
    }
}

# Build the report
$report = @()

foreach ($zone in $zones) {
    foreach ($assignment in $assignments) {

        $cloudSetIds = $assignment.appScopeIds | Where-Object { $_ -like '/CloudSet/*' }
        $sentinelIds = $assignment.appScopeIds | Where-Object { $_ -like '/SentinelScope/*' }

        # Filtering out Sentinel scopes, since we focus on cloud scopes
        if ($cloudSetIds) {
            $applies = $cloudSetIds -contains "/CloudSet/$($zone.id)"
        }
        elseif ($sentinelIds) {

            $applies = $false
        }
        else {

            $applies = $true
        }
        if (-not $applies) {
            continue
        }

        # Look up role definition and principals
        $roleDef = $roleDefLookup[$assignment.roleDefinitionId]

        $principals = @()
        foreach ($principalId in $assignment.principalIds) {
            $principals += $principalLookup[$principalId]
        }

        # permissions into a single list
        $permissions = @()
        foreach ($rp in $roleDef.rolePermissions) {
            foreach ($action in $rp.allowedResourceActions) {
                $permissions += $action
            }
        }

        $report += [pscustomobject]@{
            ZoneId = $zone.id
            ZoneName = $zone.displayName
            AssignmentName = $assignment.displayName
            AssignmentId = $assignment.id
            RoleName = $roleDef.displayName
            RoleId = $assignment.roleDefinitionId
            Principals = $principals
            Permissions = $permissions
        }
    }
}

Write-ReportLine ""
Write-ReportLine "=====================================" -ForegroundColor Yellow
Write-ReportLine "          REPORT" -ForegroundColor Yellow
Write-ReportLine "=====================================" -ForegroundColor Yellow

foreach ($zone in $zones) {

    Write-ReportLine ""
    Write-ReportLine "Scope: $($zone.displayName)" -ForegroundColor Green
    Write-ReportLine "  Id: $($zone.id)"

    $environments = $environmentsByZone[$zone.id]
    if ($environments -and $environments.Count -gt 0) {
        Write-ReportLine "  Environments:"
        foreach ($env in $environments) {
            Write-ReportLine "    * [$($env.kind)] $($env.id)"
        }
    }

    $rowsForZone = $report | Where-Object { $_.ZoneId -eq $zone.id }

    if (-not $rowsForZone) {
        Write-ReportLine "  (no assignments)" -ForegroundColor DarkGray
        continue
    }


    $rowsForZone = @($rowsForZone)

    Write-ReportLine "  Assignments: $($rowsForZone.Count)"

    foreach ($row in $rowsForZone) {
        Write-ReportLine ""
        Write-ReportLine "    - Assignment:  $($row.AssignmentName)" -ForegroundColor White
        Write-ReportLine "      Role:        $($row.RoleName)"

        Write-ReportLine "      Principals:"
        foreach ($p in $row.Principals) {
            Write-ReportLine "        * $($p.DisplayName) [$($p.Type)] - $($p.Id)"
        }

        Write-ReportLine "      Permissions:"
        if ($row.Permissions.Count -eq 0) {
            Write-ReportLine "        (none)"
        }
        else {
            foreach ($perm in $row.Permissions) {
                Write-ReportLine "        * $perm"
            }
        }
    }
}

# Export the stuff
Write-Host ""
$export = Read-Host "Do you want to export the report? (Y/N)"

if ($export -eq "Y") {

    # Default path is next to the script
    $defaultPath = Join-Path $PSScriptRoot "CloudScopePermissions_$(Get-Date -Format 'yyyy-MM-dd').txt"
    Write-Host "Default path: $defaultPath"

    $path = Read-Host "Do you want to change the default path? (Y/N)"

    if ($path -eq "Y") {
        $OutputPath = Read-Host "Enter the new path"
    }
    else {
        $OutputPath = $defaultPath
    }

    $exportLines | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host ""
    Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "Done" -ForegroundColor Green

Disconnect-MgGraph | Out-Null
