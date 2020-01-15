<#	
	.NOTES
	===========================================================================
	 Created on:   	13.12.2019
	 Created by:   	unkn0wn_root
	 Filename:     	Get-WinLog.ps1
	===========================================================================
#>
function Test-WinRM {
    [CmdletBinding()]
	param ([alias('Server')]
	[string[]]$ComputerName
	)
	
	$Output = foreach ($Computer in $ComputerName) {
        $Test = [PSCustomObject] @{
			Output = $null
            Status = $null
            ComputerName = $Computer
		}
		
        try {
            $Test.Output = Test-WSMan -ComputerName $Computer -ErrorAction Stop
            $Test.Status = [bool]$true
		} 
		
		catch { 
			$Test.Status = [bool]$false 
		}
        Write-Output $Test
    }
    return $Output
}

function Get-WinLog
{
	[CmdletBinding()]
	Param (
		[Parameter(
		Mandatory = $true,
		ValueFromPipeline,
		ValueFromPipelineByPropertyName)]
		[ValidateNotNullOrEmpty()]
		[string[]]$ComputerName,

		[Parameter()]
		[string[]]$LogName = @('Application','System','Security'),
		
		[Parameter()]
		[int[]]$ID,

		[Parameter()]
		[int]$MinusHours,

		[Parameter()]
		[int]$MinusDays
	)
	begin {
		$Events = [System.Collections.Hashtable]::new()
		if ($PSBoundParameters['MinusHours']) {
			$Time = [datetime]::Now.AddHours(-$MinusHours)
			$Events += @{StartTime = $Time}
		}
		elseif ($PSBoundParameters['MinusDays']){
			$Time = [datetime]::Now.AddDays(-$MinusDays)
			$Events += @{StartTime = $Time}
		}
	}

	process {
		foreach ($Server in $ComputerName) {
			if ((Test-WinRM -ComputerName $Server).Status -eq $false) {
				Write-Error "Couldn't connect to $Server. WinRM not enabled. Continue to next (if any)..."
				Continue
			}
			switch ($Events) {
				{ $PSBoundParameters['LogName'] -and $PSBoundParameters['ID'] } { $Events += @{LogName = $LogName; ID = $ID};break }
				{ $PSBoundParameters['ID'] } { $Events += @{ID = $ID};break }
				{ $LogName } { $Events += @{LogName = $LogName};break }
			}

			if (($ID -eq 4624) -or ($ID -eq 4625) -or ($ID -eq 4740)) {
				try {
					$LogEvents = Get-WinEvent -FilterHashTable $Events -ErrorAction Stop -ComputerName $Server
				}

				catch {
					Write-Error "Something went wrong..."
					$_.Exception.Message
					Continue
				}
				if ($ID -eq 4624) {
					foreach ($winevent in $LogEvents){
						$EventsXML = [xml]$winevent.ToXml()
						[PSCustomObject]@{
							QueryServer = $Server
							User = $EventsXML.Event.EventData.Data[5].'#text'
							ProcessName = $EventsXML.Event.EventData.Data[17].'#text'
							SourceIP = $EventsXML.Event.EventData.Data[18].'#text'
							DomainName = $EventsXML.Event.EventData.Data[6].'#text'
							Message = $winevent.Message.Substring(0, $winevent.Message.IndexOf('.'))
						}
					}
				}
				elseif ($ID -eq 4625) {
					foreach ($winevent in $LogEvents){
						$EventsXML = [xml]$winevent.ToXml()
						[PSCustomObject]@{
							QueryServer = $Server
							User = $EventsXML.Event.EventData.Data[5].'#text'
							MachineName = $EventsXML.Event.EventData.Data[13].'#text'
							SourceIP = $EventsXML.Event.EventData.Data[19].'#text'
							FailureReason = $EventsXML.Event.EventData.Data[8].'#text'
							Message = $winevent.Message.Substring(0, $winevent.Message.IndexOf('.'))
						}
					}
				}
				elseif ($ID -eq 4740) {
					foreach ($winevent in $LogEvents){
						$EventsXML = [xml]$winevent.ToXml()
						[PSCustomObject]@{
							QueryServer = $Server
							User = $EventsXML.Event.EventData.Data[0].'#text'
							UserSID = $EventsXML.Event.EventData.Data[3].'#text'
							MachineName = $EventsXML.Event.EventData.Data[1].'#text'
							LockedOutTime = $winevent.TimeCreated
							Message = $winevent.Message.Substring(0, $winevent.Message.IndexOf('.'))
						}
					}
				}
			} 
			else {
				try{
					Get-WinEvent -FilterHashTable $Events -ErrorAction Stop -ComputerName $Server | 
					Where-Object { $_.LevelDisplayName -eq "Warning" -or $_.LevelDisplayName -eq "Error" } |
					Select-Object @{n='Server'; e={$Server}},TimeCreated,ID,LevelDisplayName,Message
				}

				catch {
					$_.Exception.Message
					Continue
				}
			}
		}
	} end {}
} 