import re
import statistics
import json
from pathlib import Path

class LabAnalyzer:
    
    def __init__(self):
        self.results = {}
    
    def analyze_qos_throughput(self, priority_log, normal_log):
        """Phân tích throughput từ iperf3 logs"""
        print("\n" + "="*60)
        print("LAB C - PHÂN TÍCH THROUGHPUT")
        print("="*60)
        
        def parse_iperf_log(filename):
            throughputs = []
            with open(filename, 'r') as f:
                for line in f:
                    # Tìm dòng có throughput: [ ID] Interval ... Mbits/sec
                    match = re.search(r'(\d+\.?\d*)\s+Mbits/sec', line)
                    if match and 'sender' not in line and 'receiver' not in line:
                        throughputs.append(float(match.group(1)))
            return throughputs
        
        try:
            priority_tp = parse_iperf_log(priority_log)
            normal_tp = parse_iperf_log(normal_log)
            
            if priority_tp and normal_tp:
                print("\nPriority Traffic (h1 -> h4):")
                print(f"  Average: {statistics.mean(priority_tp):.2f} Mbps")
                print(f"  Min:     {min(priority_tp):.2f} Mbps")
                print(f"  Max:     {max(priority_tp):.2f} Mbps")
                print(f"  StdDev:  {statistics.stdev(priority_tp):.2f} Mbps")
                
                print("\nNormal Traffic (h2 -> h5):")
                print(f"  Average: {statistics.mean(normal_tp):.2f} Mbps")
                print(f"  Min:     {min(normal_tp):.2f} Mbps")
                print(f"  Max:     {max(normal_tp):.2f} Mbps")
                print(f"  StdDev:  {statistics.stdev(normal_tp):.2f} Mbps")
                
                ratio = statistics.mean(priority_tp) / statistics.mean(normal_tp)
                print(f"\n📊 Ratio (Priority/Normal): {ratio:.2f}x")
                
                if ratio > 5:
                    print("✓ QoS đang hoạt động hiệu quả!")
                else:
                    print("⚠ QoS có thể chưa được cấu hình đúng")
                
                self.results['qos_throughput'] = {
                    'priority_avg': statistics.mean(priority_tp),
                    'normal_avg': statistics.mean(normal_tp),
                    'ratio': ratio
                }
        except FileNotFoundError as e:
            print(f"❌ Không tìm thấy file: {e}")
        except Exception as e:
            print(f"❌ Lỗi: {e}")
    
    def analyze_qos_latency(self, priority_ping, normal_ping):
        """Phân tích latency từ ping logs"""
        print("\n" + "="*60)
        print("LAB C - PHÂN TÍCH LATENCY")
        print("="*60)
        
        def parse_ping_log(filename):
            latencies = []
            with open(filename, 'r') as f:
                for line in f:
                    # Tìm: time=X.XX ms
                    match = re.search(r'time=(\d+\.?\d*)\s*ms', line)
                    if match:
                        latencies.append(float(match.group(1)))
            return latencies
        
        try:
            priority_lat = parse_ping_log(priority_ping)
            normal_lat = parse_ping_log(normal_ping)
            
            if priority_lat and normal_lat:
                print("\nPriority Traffic Latency:")
                print(f"  Average: {statistics.mean(priority_lat):.3f} ms")
                print(f"  Min:     {min(priority_lat):.3f} ms")
                print(f"  Max:     {max(priority_lat):.3f} ms")
                print(f"  StdDev:  {statistics.stdev(priority_lat):.3f} ms")
                
                print("\nNormal Traffic Latency:")
                print(f"  Average: {statistics.mean(normal_lat):.3f} ms")
                print(f"  Min:     {min(normal_lat):.3f} ms")
                print(f"  Max:     {max(normal_lat):.3f} ms")
                print(f"  StdDev:  {statistics.stdev(normal_lat):.3f} ms")
                
                diff = statistics.mean(normal_lat) - statistics.mean(priority_lat)
                print(f"\n📊 Latency Difference: {diff:.3f} ms")
                
                if diff > 0:
                    print("✓ Priority traffic có latency thấp hơn")
                else:
                    print("⚠ Latency difference không rõ ràng")
                
                self.results['qos_latency'] = {
                    'priority_avg': statistics.mean(priority_lat),
                    'normal_avg': statistics.mean(normal_lat),
                    'difference': diff
                }
        except FileNotFoundError as e:
            print(f"❌ Không tìm thấy file: {e}")
        except Exception as e:
            print(f"❌ Lỗi: {e}")
    
    def analyze_lb_distribution(self, controller_log):
        """Phân tích phân phối requests từ controller log"""
        print("\n" + "="*60)
        print("LAB D - PHÂN TÍCH PHÂN PHỐI REQUESTS")
        print("="*60)
        
        try:
            backend_stats = {}
            total_connections = 0
            
            with open(controller_log, 'r') as f:
                for line in f:
                    # Tìm dòng NEW CONNECTION
                    if 'NEW CONNECTION' in line:
                        total_connections += 1
                    
                    # Tìm dòng Backend selected
                    match = re.search(r'Backend selected: (10\.0\.0\.\d+)', line)
                    if match:
                        backend_ip = match.group(1)
                        backend_stats[backend_ip] = backend_stats.get(backend_ip, 0) + 1
            
            if backend_stats:
                print(f"\nTotal Connections: {total_connections}")
                print("\nBackend Distribution:")
                
                for backend_ip, count in sorted(backend_stats.items()):
                    percentage = (count / total_connections * 100) if total_connections > 0 else 0
                    print(f"  {backend_ip}: {count:3d} requests ({percentage:5.1f}%)")
                    print(f"    {'█' * int(percentage / 2)}")
                
                # Tính độ cân bằng (coefficient of variation)
                if len(backend_stats) > 1:
                    counts = list(backend_stats.values())
                    cv = statistics.stdev(counts) / statistics.mean(counts)
                    print(f"\n📊 Coefficient of Variation: {cv:.3f}")
                    
                    if cv < 0.1:
                        print("✓ Load balancing rất tốt (phân phối đều)")
                    elif cv < 0.3:
                        print("✓ Load balancing tốt")
                    else:
                        print("⚠ Load balancing chưa đều")
                
                self.results['lb_distribution'] = {
                    'total_connections': total_connections,
                    'backend_stats': backend_stats,
                    'cv': cv if len(backend_stats) > 1 else 0
                }
        except FileNotFoundError:
            print("❌ Không tìm thấy controller log")
            print("Hint: Chạy controller với: ryu-manager lb_controller.py > lb_controller.log 2>&1")
        except Exception as e:
            print(f"❌ Lỗi: {e}")
    
    def analyze_lb_response_time(self, time_log):
        """Phân tích response time"""
        print("\n" + "="*60)
        print("LAB D - PHÂN TÍCH RESPONSE TIME")
        print("="*60)
        
        try:
            response_times = []
            
            with open(time_log, 'r') as f:
                for line in f:
                    # Parse output từ 'time curl ...'
                    # Format: real 0m0.123s
                    match = re.search(r'real\s+0m(\d+\.?\d*)s', line)
                    if match:
                        response_times.append(float(match.group(1)) * 1000)  # Convert to ms
            
            if response_times:
                print(f"\nTotal Requests: {len(response_times)}")
                print(f"\nResponse Time Statistics:")
                print(f"  Average: {statistics.mean(response_times):.2f} ms")
                print(f"  Median:  {statistics.median(response_times):.2f} ms")
                print(f"  Min:     {min(response_times):.2f} ms")
                print(f"  Max:     {max(response_times):.2f} ms")
                print(f"  StdDev:  {statistics.stdev(response_times):.2f} ms")
                
                # Percentiles
                sorted_times = sorted(response_times)
                p50 = sorted_times[len(sorted_times) // 2]
                p95 = sorted_times[int(len(sorted_times) * 0.95)]
                p99 = sorted_times[int(len(sorted_times) * 0.99)]
                
                print(f"\nPercentiles:")
                print(f"  P50: {p50:.2f} ms")
                print(f"  P95: {p95:.2f} ms")
                print(f"  P99: {p99:.2f} ms")
                
                self.results['lb_response_time'] = {
                    'avg': statistics.mean(response_times),
                    'median': statistics.median(response_times),
                    'p95': p95,
                    'p99': p99
                }
        except FileNotFoundError:
            print("❌ Không tìm thấy time log")
        except Exception as e:
            print(f"❌ Lỗi: {e}")
    
    def save_results(self, filename='lab_analysis_results.json'):
        """Lưu kết quả phân tích"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n💾 Kết quả đã lưu vào: {filename}")
    
    def generate_report(self):
        """Tạo báo cáo tổng hợp"""
        print("\n" + "="*60)
        print("BÁO CÁO TỔNG HỢP")
        print("="*60)
        
        if 'qos_throughput' in self.results:
            print("\n📊 LAB C - QoS:")
            qos_tp = self.results['qos_throughput']
            print(f"  ✓ Throughput ratio: {qos_tp['ratio']:.2f}x")
            
            if 'qos_latency' in self.results:
                qos_lat = self.results['qos_latency']
                print(f"  ✓ Latency reduction: {qos_lat['difference']:.3f} ms")
        
        if 'lb_distribution' in self.results:
            print("\n📊 LAB D - Load Balancing:")
            lb_dist = self.results['lb_distribution']
            print(f"  ✓ Total connections: {lb_dist['total_connections']}")
            print(f"  ✓ Balance CV: {lb_dist['cv']:.3f}")
            
            if 'lb_response_time' in self.results:
                lb_rt = self.results['lb_response_time']
                print(f"  ✓ Avg response time: {lb_rt['avg']:.2f} ms")
                print(f"  ✓ P95 response time: {lb_rt['p95']:.2f} ms")

def main():
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║     SDN Lab Results Analyzer                           ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    analyzer = LabAnalyzer()
    
    print("\nChọn lab để phân tích:")
    print("1. Lab C - QoS & Measurement")
    print("2. Lab D - Load Balancing")
    print("3. Cả hai labs")
    
    choice = input("\nNhập lựa chọn (1/2/3): ").strip()
    
    if choice in ['1', '3']:
        print("\n--- Analyzing Lab C ---")
        analyzer.analyze_qos_throughput('h1_priority.log', 'h2_normal.log')
        analyzer.analyze_qos_latency('h1_ping.log', 'h2_ping.log')
    
    if choice in ['2', '3']:
        print("\n--- Analyzing Lab D ---")
        analyzer.analyze_lb_distribution('lb_controller.log')
        analyzer.analyze_lb_response_time('lb_response_time.log')
    
    analyzer.generate_report()
    analyzer.save_results()

if __name__ == '__main__':
    main()