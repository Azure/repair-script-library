Param(
    [Parameter(Mandatory=$true)]
    [string]
    $Gen
)
. .\src\windows\common\setup\init.ps1

Write-Output 'Running Script Enable-NestedHyperV $Gen'
Log-Output '$Gen'
return $STATUS_SUCCESS
