. ./src/linux/common/setup/init.sh

#We store our files in /tmp
cd /tmp

while true; do
    wget -q --no-cache https://raw.githubusercontent.com/malachma/azure-auto-recover/ubuntu-image/base.sh
    if [[ $? -eq 0 ]]; then
        echo "File base.sh fetched"
        break # the file got fetched, otherwise we try this again
    fi
    sleep 1
done

#execute the base.sh app
Log-Output "Starting the recovery"
chmod 700 /tmp/base.sh
/tmp/base.sh $1 

Log-Output "Recovery script finished"

exit $STATUS_SUCCESS