echo "killer is running"

pidof python3.5 > /dev/null

while [[$? -ne 1]]
do
  echo "python is running"
  sleep 5
  pidof python3.5 > /dev/null
done

pkill -f firefox
echo "done"