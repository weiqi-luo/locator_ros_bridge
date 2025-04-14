import docker
from tabulate import tabulate
import time
import concurrent.futures
import rclpy
from rclpy.node import Node
from bosch_locator_bridge.msg import NetStats, DockerStats, SystemStats
from std_msgs.msg import Header
import subprocess
import re
import threading
import multiprocessing as mp
from multiprocessing import Process, Queue
import argparse
from scapy.all import sniff, IP
from collections import defaultdict


def create_stats_table(container_stats, net_stats):
    """Create formatted table data from container stats

    Args:
        container_stats (list): List of DockerStats messages

    Returns:
        tuple: (headers, table_data_docker) for tabulate
    """
    # Define table headers
    headers_docker = [
        "CONTAINER",
        "CPU %",
        "MEM %",
        "BLOCK INPUT (MiB)",
        "BLOCK OUTPUT (MiB)",
    ]

    # Create table data
    table_data_docker = []

    # Sort container stats by name
    sorted_stats = sorted(container_stats, key=lambda x: x.container_name.lower())

    for stat in sorted_stats:
        table_data_docker.append(
            [
                stat.container_name,
                f"{stat.cpu_percentage:.2f}%",
                f"{stat.memory_percent:.2f}%",
                f"{stat.block_input:.2f}",
                f"{stat.block_output:.2f}",
            ]
        )
        
    headers_net = [
        "INTERFACE",
        "TARGET IP",
        "RX (MiB)",
        "TX (MiB)",
        "RX RATE (B/s)",
        "TX RATE (B/s)",
        "PEAK RX (B/s)",
        "PEAK TX (B/s)",
    ]
    
    table_data_net = [
        [
            net_stats.interface,
            net_stats.target_ip,
            f"{net_stats.rx_mib:.2f}",
            f"{net_stats.tx_mib:.2f}",
            f"{net_stats.rx_rate:.2f}",
            f"{net_stats.tx_rate:.2f}",
            f"{net_stats.rx_rate_peak:.2f}",
            f"{net_stats.tx_rate_peak:.2f}",
        ]
    ]  
    return headers_docker, headers_net, table_data_docker, table_data_net


def format_bytes(bytes_value):
    """Convert bytes to human readable format"""
    for unit in ["B", "KiB", "MiB", "GiB"]:
        if bytes_value < 1024:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.2f} TiB"


def format_bandwidth(bytes_per_sec):
    """Format bandwidth in human readable format"""
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_per_sec < 1024:
            return f"{bytes_per_sec:.2f}{unit}"
        bytes_per_sec /= 1024
    return f"{bytes_per_sec:.2f}TB"


def calculate_cpu_percent(d):
    """Get CPU percentage safely"""
    cpu_stats = d.get("cpu_stats", {})
    precpu_stats = d.get("precpu_stats", {})

    # Get CPU usage stats
    cpu_usage = cpu_stats.get("cpu_usage", {})
    precpu_usage = precpu_stats.get("cpu_usage", {})

    # Calculate deltas with defaults
    cpu_delta = float(cpu_usage.get("total_usage", 0)) - float(
        precpu_usage.get("total_usage", 0)
    )
    system_delta = float(cpu_stats.get("system_cpu_usage", 0)) - float(
        precpu_stats.get("system_cpu_usage", 0)
    )

    # Get CPU count
    cpu_count = len(cpu_usage.get("percpu_usage", [])) or cpu_stats.get(
        "online_cpus", 1
    )

    return (cpu_delta / system_delta) * 100.0 * cpu_count if system_delta > 0.0 else 0.0


def calculate_memory_usage(stats):
    """Calculate actual memory usage by subtracting cache"""
    mem_stats = stats.get("memory_stats", {})
    stats_details = mem_stats.get("stats", {})

    usage = mem_stats.get("usage", 0)
    inactive_file = stats_details.get(
        "total_inactive_file", stats_details.get("inactive_file", 0)
    )

    return max(0, usage - inactive_file)


def calculate_memory_percent(stats):
    """Calculate memory percentage safely"""
    mem_stats = stats.get("memory_stats", {})
    if not mem_stats:
        return 0.0

    usage = calculate_memory_usage(stats)
    mem_limit = mem_stats.get("limit", 1)  # Default to 1 to avoid division by zero

    return (usage / mem_limit) * 100 if mem_limit > 0 else 0.0


def get_block_io_stats(stats):
    """Get block I/O stats in MiB"""
    io_stats = stats.get("blkio_stats", {}).get("io_service_bytes_recursive", [])
    block_stats = {"read": 0.0, "write": 0.0}

    for io_stat in io_stats:
        op = io_stat.get("op", "").lower()
        if op in block_stats:
            block_stats[op] = float(io_stat.get("value", 0)) / (
                1024 * 1024
            )  # Convert to MiB

    return block_stats["read"], block_stats["write"]


class DockerStatsCollector:
    def __init__(self):
        self.docker_client = docker.DockerClient(base_url="unix://var/run/docker.sock")
        self.previous_stats = {}
        self._shutdown = False
        
    def collect_stats(self):
        """Collect stats for all containers"""
        try:
            containers = sorted(self.docker_client.containers.list(), key=lambda x: x.name)
            container_stats = []
            
            for container in containers:
                stats = container.stats(stream=False)
                block_io = get_block_io_stats(stats)
                container_stats.append(DockerStats(
                    container_name=container.name,
                    cpu_percentage=calculate_cpu_percent(stats),
                    memory_percent=calculate_memory_percent(stats),
                    block_input=block_io[0],
                    block_output=block_io[1],
                ))
            
            return container_stats
            
        except Exception as e:
            print(f"Docker stats collection error: {e}")
            return []

    def cleanup(self):
        """Cleanup resources"""
        self._shutdown = True
        try:
            self.docker_client.close()
        except:
            pass


class NetworkMonitor:
    def __init__(self, interface, local_ip, target_ip):
        self.interface = interface
        self.local_ip = local_ip
        self.target_ip = target_ip
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.peak_rx_rate = 0.0
        self.peak_tx_rate = 0.0
        self.rx_rate = 0.0
        self.tx_rate = 0.0
        self.last_time = time.time()
        self._shutdown = False
        
    def packet_callback(self, pkt):
        """Process each captured packet and update counters"""
        if IP in pkt:
            packet_size = len(pkt)
            
            # Get packet direction and size
            if pkt[IP].src == self.local_ip and pkt[IP].dst == self.target_ip:
                self.tx_bytes += packet_size
            elif pkt[IP].src == self.target_ip and pkt[IP].dst == self.local_ip:
                self.rx_bytes += packet_size
            
            # Format packet info for debugging
            # direction = "TX" if pkt[IP].src == self.local_ip else "RX"
            # packet_info = (
            #     f"{direction} | Size: {format_bytes(packet_size)} | "
            #     f"Port: {pkt[IP].sport}->{pkt[IP].dport} | "
            #     f"Type: {pkt[IP].proto}"
            # )
            # print(f"Packet: {packet_info}", flush=True)

    def collect_stats(self):
        """Collect bandwidth stats using scapy"""
        try:
            # Capture packets for the interval
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                filter=f"host {self.target_ip} and host {self.local_ip}",
                timeout=5  # Capture for 1 second
            )
            
            current_time = time.time()
            time_diff = current_time - self.last_time
            
            # Calculate rates
            rx_rate = self.rx_bytes / time_diff if time_diff > 0 else 0
            tx_rate = self.tx_bytes / time_diff if time_diff > 0 else 0
            
            # Update peak rates
            self.peak_rx_rate = max(self.peak_rx_rate, rx_rate)
            self.peak_tx_rate = max(self.peak_tx_rate, tx_rate)
            
            # Reset counters
            self.rx_bytes = 0
            self.tx_bytes = 0
            self.last_time = current_time
            
            # Return a list containing single NetStats message
            return NetStats(
                interface=self.interface,
                target_ip=self.target_ip,  # Add target_ip
                rx_mib=rx_rate / (1024 * 1024),  # Convert to MiB
                tx_mib=tx_rate / (1024 * 1024),  # Convert to MiB
                rx_rate=rx_rate,
                tx_rate=tx_rate,
                rx_rate_peak=self.peak_rx_rate,
                tx_rate_peak=self.peak_tx_rate,
            )
            
        except Exception as e:
            print(f"Stats collection error: {e}")
            return None

    def cleanup(self):
        self._shutdown = True


def collector_process(collector, queue, interval):
    """Generic collector process function"""
    while rclpy.ok():
        try:
            stats = collector.collect_stats()
            queue.put(stats)
            # time.sleep(interval)
            # print(f"Collector process stats: {stats}, time: {time.time()}")
        except Exception as e:
            print(f"Collector process error: {e}")
            time.sleep(interval)


class SystemResourceMonitor(Node):
    def __init__(self, local_ip, target_ip, interface, update_interval):
        super().__init__("system_resource_monitor")
        self.publisher = self.create_publisher(SystemStats, "system_stats", 10)
        self._shutdown = False
        
        # Create collectors
        self.docker_collector = DockerStatsCollector()
        self.network_monitor = NetworkMonitor(interface, local_ip, target_ip)
        
        # Create queues for inter-process communication
        self.docker_queue = Queue()
        self.network_queue = Queue()
        
        # Create and start collector processes
        self.docker_process = Process(
            target=collector_process,
            args=(self.docker_collector, self.docker_queue, update_interval)
        )
        self.network_process = Process(
            target=collector_process,
            args=(self.network_monitor, self.network_queue, update_interval)
        )
        
        self.docker_process.start()
        self.network_process.start()
        
        # Create timer for publishing only
        self.publish_timer = self.create_timer(update_interval, self.publish_stats)
        
        # Initialize latest stats as empty lists
        self.latest_docker_stats = None
        self.latest_net_stats = None

    def publish_stats(self):
        """Non-blocking publish method that reads from queues"""
        try:
            # Get latest docker stats if available
            while not self.docker_queue.empty():
                stats = self.docker_queue.get_nowait()
                self.latest_docker_stats = stats if stats and len(stats) > 0 else None
                
            # Get latest bandwidth stats if available
            while not self.network_queue.empty():
                stats = self.network_queue.get_nowait()
                # Only take the first NetStats object since we expect a list with one item
                self.latest_net_stats = stats if stats else None
            
            # Create and publish message
            if self.latest_net_stats or self.latest_docker_stats:
                sys_msg = SystemStats()
                sys_msg.header.stamp = self.get_clock().now().to_msg()
                sys_msg.docker_stats = self.latest_docker_stats or []
                sys_msg.net_stats = [self.latest_net_stats] or []
                self.publisher.publish(sys_msg)

                headers_docker, headers_net, table_data_docker, table_data_net = \
                    create_stats_table(self.latest_docker_stats, self.latest_net_stats)
                print("\033[2J\033[H", end="")  # Clear screen and move cursor to top
                print(f"System Stats - Updated: {time.strftime('%H:%M:%S')}")
                print("=" * 100)
                print(tabulate(table_data_docker, headers=headers_docker, tablefmt="grid"))
                print(tabulate(table_data_net, headers=headers_net, tablefmt="grid"))
                
            # Update network stats display
            if self.latest_net_stats:
                print(f"Bandwidth - RX: {format_bandwidth(self.latest_net_stats.rx_rate)}/s, "
                      f"TX: {format_bandwidth(self.latest_net_stats.tx_rate)}/s")
            else:
                print("Bandwidth data not available yet")
            
        except Exception as e:
            self.get_logger().error(f'Error publishing stats: {str(e)}')
            self.get_logger().debug(f'Docker stats length: {len(self.latest_docker_stats) if self.latest_docker_stats else 0}')
            self.get_logger().debug(f'Network stats available: {self.latest_net_stats is not None}')

    def destroy_node(self):
        """Clean up processes when shutting down"""
        try:
            self._shutdown = True
            
            # Terminate collector processes
            self.docker_process.terminate()
            self.network_process.terminate()
            
            # Wait for processes to finish
            self.docker_process.join(timeout=3.0)
            self.network_process.join(timeout=3.0)
            
            # Cleanup collectors
            self.docker_collector.cleanup()
            self.network_monitor.cleanup()
            
            # Cancel publish timer
            self.publish_timer.cancel()
            
        except Exception as e:
            print(f"Error during shutdown: {e}")
        finally:
            super().destroy_node()


def main(args=None):
    parser = argparse.ArgumentParser(description='System Resource Monitor')
    parser.add_argument('--local-ip', type=str, default='192.169.81.14',
                      help='Local IP address to monitor')
    parser.add_argument('--target-ip', type=str, default='192.168.0.70',
                      help='Target IP address to monitor')
    parser.add_argument('--interface', type=str, default='wg0',
                      help='Network interface to monitor (default: wg0)')
    parser.add_argument('--update-interval', type=float, default=1.0,
                      help='Update interval in seconds (default: 1.0)')
    
    parsed_args = parser.parse_args()
    
    rclpy.init(args=args)
    monitor = None
    
    try:
        monitor = SystemResourceMonitor(
            local_ip=parsed_args.local_ip,
            target_ip=parsed_args.target_ip,
            interface=parsed_args.interface,
            update_interval=parsed_args.update_interval
        )
        rclpy.spin(monitor)
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        if monitor:
            monitor.destroy_node()
            rclpy.shutdown()
        print("Shutdown complete")


if __name__ == "__main__":
    main()



# {
#     "name": "/BoschRexrothLocalizationServer",
#     "id": "aa7f6c1e618a7dbfb61f0f15f659870db64397ee65cd126c095701f2389a19cb",
#     "read": "2025-04-09T15:48:19.143846827Z",
#     "preread": "2025-04-09T15:48:18.132227976Z",
#     "pids_stats": {"current": 510, "limit": 37996},
#     "blkio_stats": {
#         "io_service_bytes_recursive": [
#             {"major": 259, "minor": 0, "op": "read", "value": 113098752},
#             {"major": 259, "minor": 0, "op": "write", "value": 14876672},
#         ],
#     },
#     "num_procs": 0,
#     "storage_stats": {},
#     "cpu_stats": {
#         "cpu_usage": {
#             "total_usage": 642927970000,
#             "usage_in_kernelmode": 366852524000,
#             "usage_in_usermode": 276075446000,
#         },
#         "system_cpu_usage": 469471360000000,
#         "online_cpus": 32,
#         "throttling_data": {"periods": 0, "throttled_periods": 0, "throttled_time": 0},
#     },
#     "precpu_stats": {
#         "cpu_usage": {
#             "total_usage": 642879882000,
#             "usage_in_kernelmode": 366824318000,
#             "usage_in_usermode": 276055564000,
#         },
#         "system_cpu_usage": 469439500000000,
#         "online_cpus": 32,
#         "throttling_data": {"periods": 0, "throttled_periods": 0, "throttled_time": 0},
#     },
#     "memory_stats": {
#         "usage": 324579328,
#         "stats": {
#             "active_anon": 174338048,
#             "active_file": 85880832,
#             "anon": 174182400,
#             "anon_thp": 0,
#             "file": 125038592,
#             "file_dirty": 12288,
#             "file_mapped": 73408512,
#             "file_writeback": 0,
#             "inactive_anon": 0,
#             "inactive_file": 39002112,
#             "kernel_stack": 8355840,
#             "pgactivate": 0,
#             "pgdeactivate": 0,
#             "pgfault": 174241,
#             "pglazyfree": 0,
#             "pglazyfreed": 0,
#             "pgmajfault": 557,
#             "pgrefill": 0,
#             "pgscan": 0,
#             "pgsteal": 0,
#             "shmem": 155648,
#             "slab": 11024320,
#             "slab_reclaimable": 4066768,
#             "slab_unreclaimable": 6957552,
#             "sock": 0,
#             "thp_collapse_alloc": 0,
#             "thp_fault_alloc": 0,
#             "unevictable": 0,
#             "workingset_activate": 0,
#             "workingset_nodereclaim": 0,
#             "workingset_refault": 0,
#         },
#         "limit": 3327328.32 MiB / 30.99 GiB8083072,
#     },
#     "networks": {
#         "eth0": {
#             "rx_bytes": 2490257,
#             "rx_packets": 14406,
#             "rx_errors": 0,
#             "rx_dropped": 0,
#             "tx_bytes": 2795987,
#             "tx_packets": 9571,
#             "tx_errors": 0,
#             "tx_dropped": 0,
#         }
#     },
# }
