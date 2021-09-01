
Param([Parameter(Mandatory=$false)][string]$gen='1')
. .\src\windows\common\setup\init.ps1

Write-Output "Running Script Enable-NestedHyperV $gen"
Log-Output '$Gen'
return $STATUS_SUCCESS
