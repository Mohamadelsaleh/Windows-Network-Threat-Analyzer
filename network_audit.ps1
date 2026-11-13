
#collect established public TCP connections

function Get-NetworkAudit {

    param(
        [string]$OutputFile = "connections.csv"
    )

    Write-Host "Checking network connections..."

    $outputPath = Join-Path $PSScriptRoot $OutputFile

    $connections = Get-NetTCPConnection |
        Where-Object {
            $_.State -eq "Established" -and
            $_.RemoteAddress -notmatch "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1$)"
        }

    $results = @()

    foreach ($connection in $connections) {

        $processName = "Unknown"

        try {
            $process = Get-Process -Id $connection.OwningProcess -ErrorAction Stop
            $processName = $process.ProcessName
        }
        catch {
            $processName = "Unknown"
        }

        $item = [PSCustomObject]@{
            LocalAddress  = $connection.LocalAddress
            LocalPort     = $connection.LocalPort
            RemoteAddress = $connection.RemoteAddress
            RemotePort    = $connection.RemotePort
            State         = $connection.State
            PID           = $connection.OwningProcess
            ProcessName   = $processName
        }

        $results += $item
    }

    $results |
        Sort-Object RemoteAddress |
        Export-Csv -Path $outputPath -NoTypeInformation

    Write-Host "Done! Results saved to $OutputFile"
}


Get-NetworkAudit