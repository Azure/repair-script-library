function Log-Output
{
	echo "[Output $(date "+%m/%d/%Y %T")]$1"
}
function Log-Info
{
	echo "[Info $(date "+%m/%d/%Y %T")]$1"
}
function Log-Warning
{
	echo "[Warning $(date "+%m/%d/%Y %T")]$1"
}
function Log-Error
{
	echo "[Error $(date "+%m/%d/%Y %T")]$1"
}
function Log-Debug
{
	echo "[Debug $(date "+%m/%d/%Y %T")]$1"
}