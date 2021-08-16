#!/usr/bin/python3
try:
    import socket
    import sys
    import argparse
    from pwn import *
    from termcolor import colored
except ImportError as err:
    print("[-] Some libraries are missing:")
    print(err)

def serverConnection(ip, user_list):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    connect = s.connect((ip, 25))
    log.info(colored("IP: ", "green") + ip)

    # Receive the banner
    banner = s.recv(1024).decode()
    log.info(colored("Banner: ", "cyan") + banner)

    # Create progress function
    p = log.progress(colored("Probing usernames", "cyan"))

    # Checking usernames
    for user in user_list:
        # VRFY a user
        data = "VRFY " + user.strip() + "\r\n"
        data = str.encode(data)
        p.status(user)
        s.send(data)
        result = s.recv(1024).decode()

        # Checking SMTP reply codes
        codes = ["250", "251", "252"]
        if any(code in result for code in codes):
            log.info(result)

    # Progress completed successfully
    p.success("done!")

    # Close username list
    user_list.close()

    # Close the socket
    s.close()

def enumSMTPuser(ip, username_list):
    # Username list
    user_list = open(username_list, "r")

    # Call serverConnection function
    serverConnection(ip, user_list)

def multipleEnumSMTPuser(ip_address_list, username_list):
    # IP list
    ip_list = open(ip_address_list, "r")

    # Checking each IP address
    for ip in ip_list:
        # Username list
        user_list = open(username_list, "r")

        # Call serverConnection function
        ip = ip.split()[0]
        serverConnection(ip, user_list)

    # Close IP list
    ip_list.close()

def main():
    # Create parser
    parser = argparse.ArgumentParser(description="SMTP usernames enum.", add_help=False)

    # Adding arguments
    parser.add_argument("-i", "--ip", help="Target IP address")
    parser.add_argument("-m", "--mip", help="File with target IP addresses")
    parser.add_argument("-w", "--wordlist", help="Username wordlist")
    parser.add_argument("-h", "--help", action="help", help="Message help")

    # Executing the parse_args() method
    args = parser.parse_args()

    if args.ip:
        if not args.wordlist:
            parser.print_help()
            sys.exit(1)
        else:
            enumSMTPuser(args.ip, args.wordlist)
    elif args.mip:
        if not args.wordlist:
            parser.print_help()
            sys.exit(1)
        else:
            multipleEnumSMTPuser(args.mip, args.wordlist)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
