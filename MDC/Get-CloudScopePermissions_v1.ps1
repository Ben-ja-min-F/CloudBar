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

# Get zones
Write-Host "Getting zones..." -ForegroundColor Cyan
$zones = Get-AllPages -Url "https://graph.microsoft.com/beta/security/zones"
Write-Host "Found $($zones.Count) zones"

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
        # Under certain conditions Sentinel scopes will show up
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

Write-Host ""
Write-Host "=====================================" -ForegroundColor Yellow
Write-Host "          REPORT" -ForegroundColor Yellow
Write-Host "=====================================" -ForegroundColor Yellow

foreach ($zone in $zones) {

    Write-Host ""
    Write-Host "Scope: $($zone.displayName)" -ForegroundColor Green
    Write-Host "  Id: $($zone.id)"

    $rowsForZone = $report | Where-Object { $_.ZoneId -eq $zone.id }

    if (-not $rowsForZone) {
        Write-Host "  (no assignments)" -ForegroundColor DarkGray
        continue
    }


    $rowsForZone = @($rowsForZone)

    Write-Host "  Assignments: $($rowsForZone.Count)"

    foreach ($row in $rowsForZone) {
        Write-Host ""
        Write-Host "    - Assignment:  $($row.AssignmentName)" -ForegroundColor White
        Write-Host "      Role:        $($row.RoleName)"

        Write-Host "      Principals:"
        foreach ($p in $row.Principals) {
            Write-Host "        * $($p.DisplayName) [$($p.Type)] - $($p.Id)"
        }

        Write-Host "      Permissions:"
        if ($row.Permissions.Count -eq 0) {
            Write-Host "        (none)"
        } 
        else {
            foreach ($perm in $row.Permissions) {
                Write-Host "        * $perm"
            }
        }
    }
}

Write-Host ""
Write-Host "Done" -ForegroundColor Green

Disconnect-MgGraph | Out-Null
