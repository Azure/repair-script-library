Function Log-Output
{
	Param([Parameter(Mandatory=$true)][PSObject[]]$message)
	Write-Output "[Output $(Get-Date)]$message"
}
Function Log-Info
{
	Param([Parameter(Mandatory=$true)][PSObject[]]$message)
	Write-Output "[Info $(Get-Date)]$message"
}
Function Log-Warning
{
	Param([Parameter(Mandatory=$true)][PSObject[]]$message)
	Write-Output "[Warning $(Get-Date)]$message"
}
Function Log-Error
{
	Param([Parameter(Mandatory=$true)][PSObject[]]$message)
	Write-Output "[Error $(Get-Date)]$message"
}
Function Log-Debug
{
	Param([Parameter(Mandatory=$true)][PSObject[]]$message)
	Write-Output "[Debug $(Get-Date)]$message"
}
		