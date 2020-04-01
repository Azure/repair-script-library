. ./src/linux/common/setup/init.sh

#execute the base.sh app
Log-Output "Starting the recovery"
chmod 700 ./src/linux/common/helpers/azure-auto-recover/base.sh
./src/linux/common/helpers/azure-auto-recover/base.sh $1
Log-Output "Recovery script finished"

exit $STATUS_SUCCESS