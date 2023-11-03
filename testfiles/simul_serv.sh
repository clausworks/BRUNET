if [ $# -ne 3 ]; then
    echo "Args: addr start_port num_servers"; exit 1
fi

addr=$1
start_port=$2
num_servers=$3

sigint_handler() {
    echo Killing servers
    #pkill -P $$
    #echo $?
    exit 0
}

for i in $(seq 1 $num_servers); do
    p=$(($start_port + i - 1))
    echo "tcpserver ${addr} ${p} cat &"
    tcpserver ${addr} ${p} cat &
done
echo Press Ctrl-C to kill all servers

trap 'sigint_handler' INT

while :
do
    sleep 1
done

echo Failed to kill servers
exit 1
