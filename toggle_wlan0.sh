while :
do
    sudo nft flush table block_wlan0
    echo on
    sleep $1
    sudo nft -f block_wlan0.nft
    echo off
    sleep $2
done
