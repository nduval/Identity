# ============================================================================== #
#  Query to group all users flagged with DUPLICATE_PASSWORD 
# ============================================================================== #

# --- Configuration ---
$clientId = "<client_id>"
$clientSecret = "<secret>"
$baseUrl = "https://api.crowdstrike.com"
$graphqlUrl = "$baseUrl/identity-protection/combined/graphql/v1"

# --- Define Risk Factors to Query ---
$riskFactorsToQuery = @(
    "DUPLICATE_PASSWORD"
)


# --- 1. Get the Token ---
Write-Host "Requesting access token..."
$tokenUrl = "$baseUrl/oauth2/token"
$tokenBody = @{
    "client_id"     = $clientId
    "client_secret" = $clientSecret
}
try {
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $tokenBody -ErrorAction Stop
    $accessToken = $tokenResponse.access_token
    Write-Host "Token received!" -ForegroundColor Green
}
catch {
    Write-Error "Failed to get access token. Exception: $($_.Exception.Message)"
    return # Stop execution
}

$headers = @{ Authorization = "Bearer $accessToken" }

# --- 2. The Master GraphQL Query ---
$graphqlQuery = @'
query GetEntitiesByRiskFactor($first: Int, $after: Cursor, $riskFactors: [RiskFactorType!]) {
  entities(first: $first, after: $after, riskFactorTypes: $riskFactors, sortKey: RISK_SCORE, sortOrder: DESCENDING) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        entityId
        primaryDisplayName
        secondaryDisplayName
        type
        riskScore
        archived
        isAdmin: hasRole(type: AdminAccountRole)
        accounts {
          ... on ActiveDirectoryAccountDescriptor {
            passwordAttributes {
              lastChange
            }
          }
        }
        riskFactors {
          type
          score
          severity

          ... on AttackPathBasedRiskFactor {
            attackPath {
              relation
              entity {
                primaryDisplayName
                type
              }
              nextEntity {
                primaryDisplayName
                type
              }
            }
          }

          ... on DuplicatePasswordRiskEntityFactor {
            groupId
          }
        }
      }
    }
  }
}
'@


# --- 3. Paginate and Collect All Entities ---
$allEntities = [System.Collections.Generic.List[object]]::new()
$hasNextPage = $true
$afterCursor = $null
$i = 1

do {
    $graphqlVariables = @{
        first       = 1000
        after       = $afterCursor
        riskFactors = $riskFactorsToQuery
    }

    $requestBodyObject = @{
        query     = $graphqlQuery
        variables = $graphqlVariables
    }
    $jsonBody = $requestBodyObject | ConvertTo-Json -Depth 10

    Write-Host "Running Collection $i..."
    $i++
    
    try {
        $response = Invoke-RestMethod -Uri $graphqlUrl -Method Post -Headers $headers -Body $jsonBody -ContentType "application/json" -ErrorAction Stop
        
        $entitiesOnPage = $response.data.entities.edges.node
        if ($null -ne $entitiesOnPage) {
            $allEntities.AddRange($entitiesOnPage)
        }

        $hasNextPage = $response.data.entities.pageInfo.hasNextPage
        $afterCursor = $response.data.entities.pageInfo.endCursor

        Write-Host "Collected $($allEntities.Count) total entities so far..."
    }
    catch {
        Write-Warning "Caught an exception during API call. Error: $($_.Exception.Message)"
        Write-Warning "This is likely an API permission issue. Your client credentials need the correct scopes to read risk factor details."
        break # Exit the loop on failure
    }
    
    # Small delay because I think the API might have been annoyed with fast queries?
    Start-Sleep -Seconds 1

} while ($hasNextPage)

Write-Host "---"
Write-Host "Finished fetching all pages. Total entities found: $($allEntities.Count)"

# --- 4. Process and Group the Results ---
if ($allEntities.Count -gt 0) {
    Write-Host "Processing collected entities to group by shared password..." -ForegroundColor Green

    # Find the specific risk factor we care about for this entity (in case more are used)
    $flatMap = $allEntities | ForEach-Object {
        $entity = $_
        # Find ALL duplicate password risk factors for this entity
        $duplicatePasswordRisks = $entity.riskFactors | Where-Object { $_.type -eq 'DUPLICATE_PASSWORD' }
        
        # Process each one individually
        foreach ($risk in $duplicatePasswordRisks) {
            if ($risk -and $risk.groupId) {
                # Get the password last set date from the collection of accounts.
                $passwordLastSet = ($entity.accounts.passwordAttributes.lastChange | Where-Object { $_ } | Select-Object -First 1)

                # Output a new custom object for EACH risk factor instance
                [PSCustomObject]@{
                    GroupId              = $risk.groupId
                    PrimaryDisplayName   = $entity.primaryDisplayName
                    SecondaryDisplayName = $entity.secondaryDisplayName
                    IsAdmin              = $entity.isAdmin
                    Archived             = $entity.archived
                    PasswordLastSet      = if ($passwordLastSet) { Get-Date $passwordLastSet } else { $null }
                    RiskScore            = $entity.riskScore
                    EntityType           = $entity.type
                }
            }
        }
    }

    # Group the flat list by the password GroupId, and only show groups with more than one member.
    $groupedByPassword = $flatMap | Group-Object -Property GroupId | Where-Object { $_.Count -gt 1 }

    Write-Host "Found $($groupedByPassword.Count) groups of accounts sharing passwords." -ForegroundColor Yellow
    Write-Host "---"

    # Iterate through each group and display the members in a table.
    foreach ($group in $groupedByPassword) {
        Write-Host "Password Group ID: $($group.Name)" -ForegroundColor Cyan
        Write-Host "Accounts Sharing This Password: $($group.Count)"
        $group.Group | Format-Table -Property PrimaryDisplayName, SecondaryDisplayName, IsAdmin, Archived, PasswordLastSet, EntityType, RiskScore -AutoSize
        Write-Host "" # Add a blank line for readability
    }
}
else {
    Write-Host "No entities with the specified risk factors were found."
}


