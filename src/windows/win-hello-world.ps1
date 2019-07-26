Param([Parameter(Mandatory=$false)][string]$hello='Hello',[Parameter(Mandatory=$false)][string]$world='World')
. .\src\windows\common\helpers\Logger.ps1
Log-Output "$hello $world!"

return 0