python3 worker.py -c <controller_ip> -p 5000 -t 4
python3 worker.py -c <controller_ip> -p 5000 -t 4
python3 worker.py -c <controller_ip> -p 5000 -t 4

python3 controller.py -f shadow.txt -u alice -p 5000 -b 2 -k 50000 -l 3 --min-workers 1


python3 controller.py -f shadow.txt -u user1 -p 8080 -b 2 -c 10000 -k 500 -l 3

python3 worker.py -c 127.0.0.1 -p 5000 -t 4 --checkpoint-file worker1_ckpt.json


to run worker on venv

sudo apt update

run the setup_py313t.sh bash script
- chmod +x setup_py313t.sh
- ./setup_py313t.sh

source .venv/bin/activate

** if needed run pip install passlib if it is not downloaded

verify to see if it is GIL free
run
- python3 -c "import sys; print(sys._is_gil_enabled())"

Should come out as false

and now you can run your worker.