# Exports a JSON report of cloud scopes, their contents and permissions.
# View the JSON with ReportViewer.html.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId
)

#   Graph scopes:
#   Zone.Read.All                  - read the cloud scopes (zones) + environments
#   RoleManagement.Read.Defender   - read the role assignments and definitions
#   Directory.Read.All             - resolve user/group ids to names
#   Azure: RBAC read access (e.g. "Reader") on the attached management groups / subscriptions

if (Get-Module Az.Accounts) {
    throw "Az.Accounts is already loaded in this session - its auth assemblies break the Graph login. Open a NEW PowerShell window and run the script there."
}
if (-not (Get-Module -ListAvailable Az.Accounts)) {
    throw "Az.Accounts module not found. Install it with: Install-Module Az.Accounts"
}
if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
    throw "Microsoft.Graph module not found. Install it with: Install-Module Microsoft.Graph.Authentication"
}

$scopes = @("Zone.Read.All", "RoleManagement.Read.Defender", "Directory.Read.All")
Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome -ErrorAction Stop

$ctx = Get-MgContext
if (-not $ctx -or -not $ctx.Account) {
    throw "Graph connection failed - no account in the Graph context."
}
Write-Host "Connected to Graph as $($ctx.Account)" -ForegroundColor Green
Write-Host ""

$ArmBase = "https://management.azure.com"

function Get-AllPages {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url
    )

    $results = @()
    $nextUrl = $Url

    while ($nextUrl -ne $null) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUrl -ErrorAction Stop
        foreach ($item in $response.value) {
            $results += $item
        }
        $nextUrl = $response.'@odata.nextLink'
    }

    return $results
}

# Az.Accounts and the Graph module cannot share one session (their auth
# assemblies clash), so the ARM token comes from a helper process.
function Get-ArmToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    # handover via temp file instead of console output, so the token never
    # lands in PowerShell transcription logs
    $tokenFile = Join-Path $env:TEMP ("armtoken_" + [guid]::NewGuid().ToString("N") + ".tmp")

    $childScript = @'
Import-Module Az.Accounts
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx -or $ctx.Tenant.Id -ne '__TENANT__') {
    Connect-AzAccount -TenantId '__TENANT__' | Out-Null
}
$t = Get-AzAccessToken -ResourceUrl 'https://management.azure.com'
$plain = $t.Token
if ($plain -is [System.Security.SecureString]) {
    $plain = [System.Net.NetworkCredential]::new('', $plain).Password
}
Set-Content -Path '__TOKENFILE__' -Value $plain -NoNewline
'@
    $childScript = $childScript.Replace('__TENANT__', $TenantId).Replace('__TOKENFILE__', $tokenFile)

    $shell = "powershell"
    if (Get-Command pwsh -ErrorAction SilentlyContinue) {
        $shell = "pwsh"
    }

    try {
        & $shell -NoProfile -Command $childScript | Out-Null

        $token = $null
        if (Test-Path $tokenFile) {
            $token = "$(Get-Content -Path $tokenFile -Raw)".Trim()
        }
        if (-not $token) {
            throw "Could not get an ARM access token (Azure login in the helper process failed)."
        }
        return $token
    }
    finally {
        Remove-Item -Path $tokenFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-ArmRequest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    try {
        return Invoke-RestMethod -Method GET -Uri $Uri -Headers @{ Authorization = "Bearer $script:ArmToken" }
    }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 401) {
            $script:ArmToken = Get-ArmToken -TenantId $TenantId
            return Invoke-RestMethod -Method GET -Uri $Uri -Headers @{ Authorization = "Bearer $script:ArmToken" }
        }
        throw
    }
}

function Get-AllPagesArm {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $results = @()
    $nextUrl = $Uri

    while ($nextUrl -ne $null -and $nextUrl -ne "") {
        $response = Invoke-ArmRequest -Uri $nextUrl
        foreach ($item in $response.value) {
            $results += $item
        }
        $nextUrl = $response.nextLink
    }

    return $results
}

$ResourceCategoryMap = [ordered]@{
    "microsoft.compute/virtualmachines"           = "Virtual Machines"
    "microsoft.compute/virtualmachinescalesets"   = "VM Scale Sets"
    "microsoft.compute/disks"                     = "Disks"
    "microsoft.containerservice/managedclusters"  = "AKS Clusters"
    "microsoft.containerinstance/containergroups" = "Container Instances"
    "microsoft.containerregistry/registries"      = "Container Registries"
    "microsoft.app/containerapps"                 = "Container Apps"
    "microsoft.web/sites"                         = "App Services & Functions"
    "microsoft.web/serverfarms"                   = "App Service Plans"
    "microsoft.storage/storageaccounts"           = "Storage Accounts"
    "microsoft.sql/servers"                       = "SQL Servers"
    "microsoft.dbforpostgresql/flexibleservers"   = "PostgreSQL Servers"
    "microsoft.dbformysql/flexibleservers"        = "MySQL Servers"
    "microsoft.documentdb/databaseaccounts"       = "Cosmos DB Accounts"
    "microsoft.keyvault/vaults"                   = "Key Vaults"
    "microsoft.operationalinsights/workspaces"    = "Log Analytics Workspaces"
}

$ResourceProviderFallback = [ordered]@{
    "microsoft.network"  = "Networking"
    "microsoft.compute"  = "Compute (other)"
    "microsoft.insights" = "Monitoring"
    "microsoft.web"      = "Web (other)"
}

function Get-ResourceCategory {
    param([string]$Type)

    $t = "$Type".ToLower()
    if ($ResourceCategoryMap.Contains($t)) {
        return $ResourceCategoryMap[$t]
    }

    $provider = $t.Split('/')[0]
    if ($ResourceProviderFallback.Contains($provider)) {
        return $ResourceProviderFallback[$provider]
    }

    return "Other"
}

$subscriptionCache = @{}

function Resolve-Subscription {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        [string]$DisplayName = ""
    )

    $key = $SubscriptionId.ToLower()
    if ($subscriptionCache.ContainsKey($key)) {
        return $subscriptionCache[$key]
    }

    $sub = [ordered]@{
        id             = $SubscriptionId
        name           = if ($DisplayName) { $DisplayName } else { $SubscriptionId }
        state          = $null
        resourceCount  = 0
        resourceGroups = @()
        error          = $null
    }

    try {
        $info = Invoke-ArmRequest -Uri "$ArmBase/subscriptions/$SubscriptionId`?api-version=2022-12-01"
        $sub.name = $info.displayName
        $sub.state = $info.state

        Write-Host "  Subscription: $($sub.name)" -ForegroundColor Gray

        $groups = Get-AllPagesArm -Uri "$ArmBase/subscriptions/$SubscriptionId/resourcegroups?api-version=2021-04-01"
        $resources = Get-AllPagesArm -Uri "$ArmBase/subscriptions/$SubscriptionId/resources?api-version=2021-04-01"

        $resourcesByGroup = @{}
        foreach ($res in $resources) {
            $rgName = "(none)"
            if ($res.id -match '(?i)/resourceGroups/([^/]+)/') {
                $rgName = $Matches[1]
            }
            $rgKey = $rgName.ToLower()
            if (-not $resourcesByGroup.ContainsKey($rgKey)) {
                $resourcesByGroup[$rgKey] = @()
            }
            $resourcesByGroup[$rgKey] += $res
        }

        foreach ($rg in ($groups | Sort-Object name)) {
            $rgKey = $rg.name.ToLower()
            $rgResources = @()
            if ($resourcesByGroup.ContainsKey($rgKey)) {
                $rgResources = $resourcesByGroup[$rgKey]
            }

            $byCategory = [ordered]@{}
            foreach ($res in $rgResources) {
                $category = Get-ResourceCategory $res.type
                if (-not $byCategory.Contains($category)) {
                    $byCategory[$category] = @()
                }
                $byCategory[$category] += [ordered]@{
                    name     = $res.name
                    type     = $res.type
                    location = $res.location
                }
            }

            $categories = @()
            foreach ($categoryName in ($byCategory.Keys | Sort-Object)) {
                $items = @($byCategory[$categoryName] | Sort-Object { $_.name })
                $categories += [ordered]@{
                    category  = $categoryName
                    count     = $items.Count
                    resources = $items
                }
            }

            $sub.resourceGroups += [ordered]@{
                name          = $rg.name
                location      = $rg.location
                resourceCount = $rgResources.Count
                categories    = $categories
            }
            $sub.resourceCount += $rgResources.Count
        }
    }
    catch {
        $sub.error = "Could not read subscription contents: $($_.Exception.Message)"
        Write-Warning "Subscription $SubscriptionId : $($sub.error)"
    }

    $subscriptionCache[$key] = $sub
    return $sub
}

function Resolve-ManagementGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MgName
    )

    $root = [ordered]@{
        id            = $MgName
        name          = $MgName
        children      = @()
        subscriptions = @()
        error         = $null
    }

    try {
        $info = Invoke-ArmRequest -Uri "$ArmBase/providers/Microsoft.Management/managementGroups/$MgName`?api-version=2020-05-01"
        if ($info.properties.displayName) {
            $root.name = $info.properties.displayName
        }

        Write-Host "  Management group: $($root.name)" -ForegroundColor Gray

        # descendants is a flat list with parent pointers - build the tree
        $descendants = Get-AllPagesArm -Uri "$ArmBase/providers/Microsoft.Management/managementGroups/$MgName/descendants?api-version=2020-05-01"

        $rootArmId = "/providers/Microsoft.Management/managementGroups/$MgName"
        $mgNodes = @{}
        $mgNodes[$rootArmId.ToLower()] = $root

        foreach ($d in $descendants) {
            if ($d.type -like "*managementGroups*") {
                $mgNodes[$d.id.ToLower()] = [ordered]@{
                    id            = $d.name
                    name          = if ($d.properties.displayName) { $d.properties.displayName } else { $d.name }
                    children      = @()
                    subscriptions = @()
                    error         = $null
                }
            }
        }

        foreach ($d in $descendants) {
            $parent = $root
            $parentId = $d.properties.parent.id
            if ($parentId -and $mgNodes.ContainsKey($parentId.ToLower())) {
                $parent = $mgNodes[$parentId.ToLower()]
            }

            if ($d.type -like "*managementGroups*") {
                $parent.children += $mgNodes[$d.id.ToLower()]
            }
            else {
                $parent.subscriptions += Resolve-Subscription -SubscriptionId $d.name -DisplayName $d.properties.displayName
            }
        }
    }
    catch {
        $root.error = "Could not read management group: $($_.Exception.Message)"
        Write-Warning "Management group $MgName : $($root.error)"
    }

    return $root
}

function Resolve-Environment {
    param($Environment)

    $node = [ordered]@{
        kind            = "$($Environment.kind)"
        rawId           = "$($Environment.id)"
        type            = "external"
        name            = "$($Environment.id)"
        managementGroup = $null
        subscription    = $null
    }

    if ($node.rawId -match '(?i)/providers/Microsoft\.Management/managementGroups/([^/]+)$') {
        $node.type = "managementGroup"
        $node.managementGroup = Resolve-ManagementGroup -MgName $Matches[1]
        $node.name = $node.managementGroup.name
    }
    elseif ($node.rawId -match '(?i)/subscriptions/([0-9a-fA-F-]{36})$') {
        $node.type = "subscription"
        $node.subscription = Resolve-Subscription -SubscriptionId $Matches[1]
        $node.name = $node.subscription.name
    }

    return $node
}

Write-Host "Getting Azure (ARM) access token..." -ForegroundColor Cyan
$script:ArmToken = Get-ArmToken -TenantId $TenantId
Write-Host "Got ARM token" -ForegroundColor Green

Write-Host "Getting zones..." -ForegroundColor Cyan
$zones = Get-AllPages -Url "https://graph.microsoft.com/beta/security/zones"
Write-Host "Found $($zones.Count) zones"

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
        $def = Invoke-MgGraphRequest -Method GET -Uri $url -ErrorAction Stop
        $roleDefLookup[$defId] = $def
    } catch {
        Write-Warning "Could not fetch role definition $defId"
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
            $obj = Invoke-MgGraphRequest -Method GET -Uri $url -ErrorAction Stop

            $type = $obj.'@odata.type' -replace '#microsoft.graph.', ''

            $name = $obj.displayName
            if (-not $name) {
                $name = $obj.userPrincipalName
            }
            if (-not $name) {
                $name = "(unknown)"
            }

            $principalLookup[$principalId] = [ordered]@{
                id          = $principalId
                displayName = $name
                type        = $type
            }
        }
        catch {
            $principalLookup[$principalId] = [ordered]@{
                id          = $principalId
                displayName = "(could not resolve)"
                type        = "unknown"
            }
        }
    }
}

Write-Host "Getting environments and their contents..." -ForegroundColor Cyan
$environmentsByZone = @{}
foreach ($zone in $zones) {
    Write-Host "Scope: $($zone.displayName)" -ForegroundColor White
    $resolved = @()
    try {
        $url = "https://graph.microsoft.com/beta/security/zones/$($zone.id)/environments"
        $environments = Get-AllPages -Url $url
        foreach ($environment in $environments) {
            $resolved += Resolve-Environment -Environment $environment
        }
    }
    catch {
        Write-Warning "Could not fetch environments for zone $($zone.displayName) ($($zone.id))"
    }
    $environmentsByZone[$zone.id] = $resolved
}

$scopeObjects = @()

foreach ($zone in $zones) {

    $zoneAssignments = @()

    foreach ($assignment in $assignments) {

        $cloudSetIds = $assignment.appScopeIds | Where-Object { $_ -like '/CloudSet/*' }
        $sentinelIds = $assignment.appScopeIds | Where-Object { $_ -like '/SentinelScope/*' }

        if ($cloudSetIds) {
            $applies = $cloudSetIds -contains "/CloudSet/$($zone.id)"
            $appliesVia = "Cloud scope"
        }
        elseif ($sentinelIds) {
            $applies = $false
            $appliesVia = ""
        }
        else {
            $applies = $true
            $appliesVia = "Tenant-wide"
        }
        if (-not $applies) {
            continue
        }

        $roleDef = $roleDefLookup[$assignment.roleDefinitionId]

        $principals = @()
        foreach ($principalId in $assignment.principalIds) {
            $principals += $principalLookup[$principalId]
        }

        $permissions = @()
        foreach ($rp in $roleDef.rolePermissions) {
            foreach ($action in $rp.allowedResourceActions) {
                $permissions += $action
            }
        }

        $zoneAssignments += [ordered]@{
            name        = $assignment.displayName
            role        = $roleDef.displayName
            appliesVia  = $appliesVia
            principals  = $principals
            permissions = @($permissions | Sort-Object)
        }
    }

    $scopeObjects += [ordered]@{
        id           = $zone.id
        name         = $zone.displayName
        description  = "$($zone.description)"
        environments = @($environmentsByZone[$zone.id])
        assignments  = @($zoneAssignments | Sort-Object { $_.role }, { $_.name })
    }
}

$reportData = [ordered]@{
    generatedAt = (Get-Date).ToString("o")
    tenantId    = $TenantId
    account     = "$($ctx.Account)"
    scopes      = $scopeObjects
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Yellow
Write-Host "          SUMMARY" -ForegroundColor Yellow
Write-Host "=====================================" -ForegroundColor Yellow
foreach ($scope in $scopeObjects) {
    Write-Host ""
    Write-Host "Scope: $($scope.name)" -ForegroundColor Green
    Write-Host "  Environments: $($scope.environments.Count)"
    Write-Host "  Assignments:  $($scope.assignments.Count)"
}
$totalResources = 0
foreach ($sub in $subscriptionCache.Values) {
    $totalResources += $sub.resourceCount
}
Write-Host ""
Write-Host "Resolved $($subscriptionCache.Count) subscriptions with $totalResources resources total"

$dateStamp = Get-Date -Format 'yyyy-MM-dd'
$jsonPath = Join-Path $PSScriptRoot "CloudScopeReport_$dateStamp.json"

$json = ConvertTo-Json -InputObject $reportData -Depth 100
$json | Out-File -FilePath $jsonPath -Encoding utf8
Write-Host ""
Write-Host "JSON saved to: $jsonPath" -ForegroundColor Green
Write-Host "View it by opening ReportViewer.html in a browser and clicking 'Load JSON...'"

Write-Host ""
Write-Host "Done" -ForegroundColor Green

Disconnect-MgGraph | Out-Null
