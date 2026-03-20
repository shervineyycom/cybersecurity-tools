def log_packet(data):
    with open("packets_log.txt","a")as file:
        file.write(data + "\n")
