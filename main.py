#!/usr/bin/python3
import argparse
import logging
import sys
import util.iec104
import util.mms
import util.goose
import util.sampled_values
import util.modbus


def main():
    parser = argparse.ArgumentParser(description="Electric Fuzzer")
    parser.add_argument("--host", action="store", dest="host",
                        type=str, required=False,
                        help="target host to fuzz"
    )
    parser.add_argument("--port", action="store", dest="port",
                        type=str, required=False,
                        help="target port"
    )
    parser.add_argument("--interface", action="store", dest="interface",
                        type=str, required=False,
                        help="target interface"
    )
    parser.add_argument("--service", action="store", dest="service",
                        type=str, required=True,
                        help="target service"
    )

    args = parser.parse_args()
    host = args.host
    port = args.port
    service = args.service
    interface = args.interface

    if host != None and port != None:
        if util.iec104.isServiceExposed(host, port):
            logging.info("Service found active on %s:%s" % (host,port))
        else:
            logging.warn("Service is not exposed by %s on %s port" % (host,port))
            logging.info("Stopping Fuzzing on %s:%s" % (host,port))

    if service.upper() == "IEC104":
        util.iec104.IEC104Fuzz(host, port)
    elif service.upper() == "MMS":
        util.mms.MMSFuzz(host, port)
    elif service.upper() == "GOOSE":
        util.goose.GOOSEFuzz(interface)
    elif service.upper() == "SV":
        util.sampled_values.SVFuzz(interface)
    elif service.upper() == "MODBUS":
        util.modbus.ModbusFuzz(host, port)
    else:
        logging.info("Unsupported Service!")
        sys.exit(0)

    logging.info("Electric Fuzzing is finished... bye.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(message)s',
                        datefmt='%d-%b-%y %H:%M:%S')
    main()

