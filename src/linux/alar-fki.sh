. ./src/linux/common/setup/init.sh

#execute the base.sh app
Log-Output "Starting the recovery"
chmod 700 ./src/linux/common/helpers/alar/base.sh
./src/linux/common/helpers/alar/base.sh $1
error=$?
Log-Output "Recovery script finished"

if [[ ${error} -eq 11 ]]; then
# exit code 11 from base.sh points out to a severe issue
    exit $STATUS_ERROR
else
    exit $STATUS_SUCCESS
fi