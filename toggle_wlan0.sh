if [ $# -ne 2 ]; then
    echo "Args: time_on time_off"; exit 1
fi

time_on=$1
time_off=$2

sudo nft flush table block_wlan0
while :
do
    sudo nft -f block_wlan0.nft
    echo off
    sleep $time_off
    sudo nft delete table block_wlan0
    echo on
    sleep $time_on
done
