#sudo iw wlan0 set type ibss
#sudo ip link set wlan0 up
sudo iw wlan0 ibss leave
sudo iw wlan0 ibss join "PiFi" 2432
sleep 3
iw wlan0 info

#sudo batctl if add wlan0
#sudo ifconfig wlan0 up
#sudo ifconfig bat0 up
