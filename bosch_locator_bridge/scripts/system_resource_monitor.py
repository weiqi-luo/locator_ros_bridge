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


def format_bytes(bytes_value):
    """Convert bytes to human readable format"""
    for unit in ["B", "KiB", "MiB", "GiB"]:
        if bytes_value < 1024:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.2f} TiB"

def format_bandwidth(bytes_per_sec):
    """Format bandwidth in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_per_sec < 1024:
            return f"{bytes_per_sec:.2f}{unit}"
        bytes_per_sec /= 1024
    return f"{bytes_per_sec:.2f}TB"

def parse_bandwidth_value(value_str):
    """Parse bandwidth values like '52B', '1.5Kb', etc."""
    try:
        if not value_str:
            return 0.0
        
        # Extract number and unit
        match = re.match(r'([\d.]+)([KMGkMGT]?[Bb])?', value_str)
        if not match:
            return 0.0
            
        value = float(match.group(1))
        unit = (match.group(2) or 'B').upper()
        
        # Convert to bytes
        multipliers = {
            'B': 1,
            'KB': 1024,
            'MB': 1024**2,
            'GB': 1024**3,
            'TB': 1024**4
        }
        
        # Handle both 'B' and 'b' (bytes vs bits)
        if unit.endswith('B'):
            return value * multipliers.get(unit, 1)
        else:  # Convert bits to bytes
            return (value * multipliers.get(unit.replace('b', 'B'), 1)) / 8
                
    except Exception as e:
        print(f"Error parsing bandwidth value '{value_str}': {e}")
        return 0.0

def calculate_cpu_percent(d):
    cpu_count = len(d["cpu_stats"]["cpu_usage"].get("percpu_usage", [])) or d["cpu_stats"].get("online_cpus", 1)
    cpu_delta = float(d["cpu_stats"]["cpu_usage"]["total_usage"]) - float(d["precpu_stats"]["cpu_usage"]["total_usage"])
    system_delta = float(d["cpu_stats"]["system_cpu_usage"]) - float(d["precpu_stats"]["system_cpu_usage"])
    return (cpu_delta / system_delta) * 100.0 * cpu_count if system_delta > 0.0 else 0.0

def calculate_memory_usage(d):
    usage = d["memory_stats"].get("usage", 0)
    if "total_inactive_file" in d["memory_stats"].get("stats", {}):
        usage = usage - d["memory_stats"]["stats"]["total_inactive_file"]
    elif "inactive_file" in d["memory_stats"].get("stats", {}):
        usage = usage - d["memory_stats"]["stats"]["inactive_file"]
    return usage

class DockerStatsMonitor(Node):
    def __init__(self):
        super().__init__('docker_stats_monitor')
        
        # Add shutdown control flag
        self._shutdown = False
        
        # Declare parameters
        self.declare_parameter('target_ip', '192.168.0.70')
        self.declare_parameter('interface', 'wg0')
        self.target_ip = self.get_parameter('target_ip').value
        self.interface = self.get_parameter('interface').value
        self.get_logger().info(f'Monitoring bandwidth for IP: {self.target_ip} on interface: {self.interface}')
        
        # Create three timers for different tasks
        self.container_timer = self.create_timer(1.0, self.collect_container_stats)
        # self.bandwidth_timer = self.create_timer(1.0, self.collect_bandwidth_stats)
        self.publish_timer = self.create_timer(1.0, self.publish_system_stats)
        
        # Create publisher
        self.publisher = self.create_publisher(SystemStats, 'docker_stats', 10)

        # Store collected data
        self.last_bandwidth = (0.0, 0.0)
        self.container_stats = []
        
        # Add storage for previous network stats
        self.previous_stats = {}  # container_name -> (ros_time, rx_bytes, tx_bytes)
        
    def collect_container_stats(self):
        """Collect container stats periodically"""
        try:
            docker_client = docker.DockerClient(base_url="unix://var/run/docker.sock")
            containers = sorted(docker_client.containers.list(), key=lambda x: x.name)
            container_stats = []
            
            # Collect container stats in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(containers)) as executor:
                futures = [executor.submit(self.get_container_stats, container) for container in containers]
                for future in concurrent.futures.as_completed(futures):
                    stat = future.result()
                    if stat is not None:
                        container_stats.append(stat)

            self.container_stats = container_stats
            
        except Exception as e:
            self.get_logger().error(f'Error collecting container stats: {str(e)}')

    def collect_bandwidth_stats(self):
        """Collect bandwidth stats periodically"""
        try:
            rx_rate, tx_rate = self.get_bandwidth_stats(self.target_ip)
            self.last_bandwidth = (rx_rate, tx_rate)
        except Exception as e:
            self.get_logger().error(f'Error collecting bandwidth stats: {str(e)}')

    def get_container_stats(self, container):
        try:
            stats = container.stats(stream=False)
            current_time = self.get_clock().now().nanoseconds / 1e9  # Convert to seconds
            
            # Calculate stats
            cpu_percent = calculate_cpu_percent(stats)
            mem_usage = calculate_memory_usage(stats)
            mem_limit = stats["memory_stats"].get("limit", 0)
            mem_percent = (mem_usage/mem_limit) * 100 if mem_limit else 0
            
            # Get current network stats for the specified interface
            if self.interface not in stats["networks"]:
                self.get_logger().warn(f"Interface {self.interface} not found in container {container.name}")
                return None
                
            current_rx = stats["networks"][self.interface]["rx_bytes"]
            current_tx = stats["networks"][self.interface]["tx_bytes"]
            
            # Calculate bandwidth rates
            rx_rate = 0.0
            tx_rate = 0.0
            
            if container.name in self.previous_stats:
                prev_time, prev_rx, prev_tx = self.previous_stats[container.name]
                time_diff = current_time - prev_time
                if time_diff > 0:
                    rx_rate = (current_rx - prev_rx) / time_diff  # bytes per second
                    tx_rate = (current_tx - prev_tx) / time_diff  # bytes per second
                    
            # Store current stats for next calculation
            self.previous_stats[container.name] = (current_time, current_rx, current_tx)
            
            # Create DockerStats message
            docker_stat = DockerStats()
            docker_stat.container_name = container.name
            docker_stat.cpu_percentage = float(cpu_percent)
            docker_stat.memory_percent = float(mem_percent)
            # Add net stats
            docker_stat.net_stats.interface = self.interface
            docker_stat.net_stats.target_ip = self.target_ip
            docker_stat.net_stats.rx_bytes = current_rx
            docker_stat.net_stats.tx_bytes = current_tx
            docker_stat.net_stats.rx_bandwidth = float(rx_rate)
            docker_stat.net_stats.tx_bandwidth = float(tx_rate)
            
            return docker_stat
            
        except Exception as e:
            self.get_logger().error(f'Error getting stats for {container.name}: {str(e)}')
            return None

    def get_bandwidth_stats(self, ip_address):
        """Get bandwidth stats using iftop for a specific IP"""
        cmd = f"sudo iftop -i {self.interface} -t -n -N -L 1 -B -f 'host {ip_address}' -s 1 2>/dev/null"
        
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True,
        )

        if result.returncode != 0:
            raise Runtimeerror (f"iftop failed with error: {result.stderr}")
            return 0.0, 0.0

        output = result.stdout
        rx_rate = tx_rate = 0.0
        
        # Parse the output line by line
        lines = output.split('\n')
        for i, line in enumerate(lines):
            line = line.strip()
            if ip_address in line:
                if "=>" in line:  # This is TX (sending)
                    parts = line.split()
                    if len(parts) >= 4:
                        tx_rate = parse_bandwidth_value(parts[-3])
                elif "<=" in line:  # This is RX (receiving)
                    parts = line.split()
                    if len(parts) >= 4:
                        rx_rate = parse_bandwidth_value(parts[-3])

        return rx_rate, tx_rate

    def publish_system_stats(self):
        """Publish collected stats periodically"""
        try:
            # Create SystemStats message
            sys_msg = SystemStats()
            sys_msg.header.stamp = self.get_clock().now().to_msg()
            sys_msg.header.frame_id = "docker_stats"
            
            # Add bandwidth info to SystemStats
            # rx_rate, tx_rate = self.last_bandwidth
            # sys_msg.bandwidth = Bandwidth()
            # sys_msg.bandwidth.interface = self.interface
            # sys_msg.bandwidth.target_ip = self.target_ip
            # sys_msg.bandwidth.rx_bandwidth = float(rx_rate)
            # sys_msg.bandwidth.tx_bandwidth = float(tx_rate)
            
            # Add container stats
            sys_msg.docker_stats = self.container_stats
            
            # Publish system stats message
            self.publisher.publish(sys_msg)
            
            # Create table for display
            table_data = []
            
            # Add bandwidth info to table
            table_data.append([
                "Bandwidth",
                "---",
                "---",
                f"{self.interface}:{self.target_ip}",
                f"{format_bandwidth(rx_rate)}/s",
                f"{format_bandwidth(tx_rate)}/s"
            ])
            
            # Add container stats to table
            for stat in self.container_stats:
                table_data.append([
                    stat.container_name,
                    f"{stat.cpu_percentage:.2f}%",
                    f"{stat.memory_percent:.2f}%",
                    "---",
                    "---",
                    "---"
                ])
            
            # Print table
            headers = ["CONTAINER", "CPU %", "MEM %", "IP", "RX RATE", "TX RATE"]
            print(f"\nSystem Stats - Updated: {time.strftime('%H:%M:%S')}")
            print("=" * 100)
            print(tabulate(table_data, headers=headers, tablefmt="simple"))

        except Exception as e:
            self.get_logger().error(f'Error in publish_system_stats: {str(e)}')

    def destroy_node(self):
        """Clean up resources when shutting down"""
        try:
            # Set shutdown flag first
            self._shutdown = True
            
            # Cancel all timers
            self.container_timer.cancel()
            self.bandwidth_timer.cancel()
            self.publish_timer.cancel()
            
            # Kill any remaining iftop processes
            subprocess.run(["sudo", "pkill", "iftop"], check=False)
            
            # Clean up Docker client
            if hasattr(self, 'docker_client'):
                self.docker_client.close()
            
        except Exception as e:
            print(f"Error during shutdown: {e}")
        finally:
            super().destroy_node()

def main(args=None):
    rclpy.init(args=args)
    monitor = None
    
    try:
        monitor = DockerStatsMonitor()
        rclpy.spin(monitor)
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        if monitor is not None:
            # Cancel all timers first
            monitor.container_timer.cancel()
            monitor.bandwidth_timer.cancel()
            monitor.publish_timer.cancel()
            # Set shutdown flag
            monitor._shutdown = True
            # Destroy node
            monitor.destroy_node()
        rclpy.try_shutdown()
        print("Shutdown complete")

if __name__ == '__main__':
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
