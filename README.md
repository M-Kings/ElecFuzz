# ElecFuzz
fuzz IEC-104协议
```
python3 main.py --host 192.168.161.25 --port 2404 --service IEC104
```

fuzz MMS协议
```
python3 main.py --host 192.168.161.25 --port 102 --service MMS
```

fuzz Modbus协议
```
python3 main.py --host 192.168.161.25 --port 502 --service MODBUS
```

fuzz GOOSE协议
```
python3 main.py --service GOOSE --interface eth1
```

fuzz SV协议
```
python3 main.py --service SV --interface eth1
```

