# sudo apt install python3-psutil
#!/usr/bin/env python3
import time
import psutil
import sys

def get_network_speed(interface='eth0'):
    old_stats = psutil.net_io_counters(pernic=True)[interface]
    time.sleep(1)
    new_stats = psutil.net_io_counters(pernic=True)[interface]
    
    download = (new_stats.bytes_recv - old_stats.bytes_recv) / 1024 
    upload = (new_stats.bytes_sent - old_stats.bytes_sent) / 1024 
    
    return download, upload

def draw_simple_graph(download, upload, max_speed=8000):

    sys.stdout.write("\033[H\033[J")
    
    print("=== Network Speed Monitor ===")
    print(f"Download: {download:.1f} KB/s")
    print(f"Upload:   {upload:.1f} KB/s\n")
    
    print("Speed Scale (KB/s):")
    print("Download: [" + "#" * int(download/max_speed*20) + "]")
    print("Upload:   [" + "#" * int(upload/max_speed*20) + "]")
    
    print("\nTime: 0-----15-----30-----45-----60 sec")

if __name__ == "__main__":
    try:
        print("Starting network monitor...")
        print("Press Ctrl+C to exit\n")
        time.sleep(2)
        
        while True:
            download, upload = get_network_speed()
            draw_simple_graph(download, upload)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
