echo "kill is running"
pidof python3.5 > /dev/null

if [[ $? -ne 0]]; then
  echo "python is not running"
  pkill -f firefox
fi