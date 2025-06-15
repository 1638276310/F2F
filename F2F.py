import base64
import os
import argparse
import math
import hashlib
import sys
import time
import zlib
import lzma
import gzip
import bz2
import getpass
import re
import platform
import psutil
import json
import logging
import shutil
import tempfile
import mmap
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import binascii

# 仅在Unix/Linux系统上导入resource模块
if os.name == 'posix':
    import resource

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('file_encoder.log', mode='w', encoding='utf-8')
    ]
)
logger = logging.getLogger('FileEncoder')
logger.setLevel(logging.INFO)

# 默认块大小 (3的倍数)
DEFAULT_CHUNK_SIZE = 3 * 1024 * 1024  # 3MB
MAX_CHUNK_SIZE = 100 * 1024 * 1024    # 100MB最大块
MIN_CHUNK_SIZE = 3                    # 3字节最小块

# 支持的编码格式
ENCODING_FORMATS = {
    'base64': (base64.b64encode, base64.b64decode, "Base64标准编码", 4/3),
    'base32': (base64.b32encode, base64.b32decode, "Base32编码", 8/5),
    'base16': (base64.b16encode, base64.b16decode, "Base16/Hex编码", 2),
    'base85': (base64.b85encode, base64.b85decode, "Base85高效编码", 5/4),
    'hex': (lambda x: binascii.hexlify(x).decode(), lambda x: binascii.unhexlify(x), "十六进制编码", 2),
    'urlsafe': (base64.urlsafe_b64encode, base64.urlsafe_b64decode, "URL安全Base64", 4/3),
}

# 支持的压缩算法
COMPRESSION_FORMATS = {
    'none': (lambda x: x, lambda x: x, "无压缩", 1.0),
    'zlib': (zlib.compress, zlib.decompress, "Zlib压缩", 0.7),
    'gzip': (gzip.compress, gzip.decompress, "Gzip压缩", 0.7),
    'lzma': (lzma.compress, lzma.decompress, "LZMA高压缩", 0.5),
    'bz2': (bz2.compress, bz2.decompress, "BZ2压缩", 0.6),
}

# 内存优化配置
MAX_MEMORY_USAGE_PERCENT = 80  # 最大内存使用百分比
MEMORY_CHECK_INTERVAL = 0.3    # 内存检查间隔(秒)

# 注册信号处理
def signal_handler(sig, frame):
    """处理Ctrl+C信号"""
    logger.info("\n操作被用户中断。正在清理...")
    sys.exit(1)

signal.signal(signal.SIGINT, signal_handler)

# 仅在Unix/Linux系统上设置文件描述符限制
if os.name == 'posix':
    try:
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_limit = min(10000, hard_limit)
        resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, hard_limit))
        logger.info(f"文件描述符限制设置为: {new_limit}/{hard_limit}")
    except Exception as e:
        logger.warning(f"无法设置文件描述符限制: {str(e)}")
else:
    logger.info("Windows系统跳过文件描述符限制设置")

class ResourceMonitor:
    """系统资源监控器"""
    def __init__(self):
        self.start_time = time.time()
        self.start_mem = psutil.virtual_memory().used
        self.max_mem = self.start_mem
        self.cpu_peak = 0
        self.last_check = time.time()
        
    def update(self):
        current_time = time.time()
        # 限制检查频率
        if current_time - self.last_check < MEMORY_CHECK_INTERVAL:
            return
            
        self.last_check = current_time
        mem = psutil.virtual_memory()
        self.max_mem = max(self.max_mem, mem.used)
        self.cpu_peak = max(self.cpu_peak, psutil.cpu_percent())
        
    def report(self):
        elapsed = time.time() - self.start_time
        mem_used = (self.max_mem - self.start_mem) / (1024 * 1024)
        return {
            "time": elapsed,
            "memory": mem_used,
            "cpu_peak": self.cpu_peak
        }

class ProgressTracker:
    """进度跟踪和显示类"""
    def __init__(self, total_chunks, total_size, operation):
        self.total_chunks = total_chunks
        self.total_size = total_size
        self.operation = operation
        self.processed_chunks = 0
        self.processed_bytes = 0
        self.start_time = time.time()
        self.last_update = 0
        self.completed = False
        self.resource_monitor = ResourceMonitor()
        self.last_chunk_time = self.start_time
        self.speed_history = []
        self.estimated_time = 0
    
    def update(self, chunk_index, chunk_size):
        """更新进度"""
        self.processed_chunks += 1
        self.processed_bytes += chunk_size
        self.resource_monitor.update()
        
        current_time = time.time()
        time_diff = current_time - self.last_chunk_time
        
        # 计算瞬时速度
        if time_diff > 0 and chunk_size > 0:
            speed = chunk_size / time_diff
            self.speed_history.append(speed)
            # 保留最近10个速度值
            if len(self.speed_history) > 10:
                self.speed_history.pop(0)
        
        self.last_chunk_time = current_time
        
        # 限制更新频率（每秒最多3次）
        if current_time - self.last_update < 0.3 and not (self.processed_chunks == self.total_chunks):
            return
        
        self.last_update = current_time
        self._display_progress()
    
    def _display_progress(self):
        """显示当前进度"""
        elapsed = time.time() - self.start_time
        if self.total_chunks > 0:
            percent = min(100, self.processed_chunks / self.total_chunks * 100)
        else:
            percent = 100 if self.processed_bytes >= self.total_size else 0
        
        # 计算平均速度
        if self.speed_history:
            avg_speed = sum(self.speed_history) / len(self.speed_history)
        elif elapsed > 0:
            avg_speed = self.processed_bytes / elapsed
        else:
            avg_speed = 0
        
        # 计算剩余时间
        remaining_bytes = self.total_size - self.processed_bytes
        if avg_speed > 0:
            remaining_time = remaining_bytes / avg_speed
        else:
            remaining_time = 0
        self.estimated_time = remaining_time
        
        # 获取内存信息
        mem_info = psutil.virtual_memory()
        mem_used = (mem_info.used - self.resource_monitor.start_mem) / (1024 * 1024)
        mem_percent = mem_info.percent
        
        # 格式化显示
        sys.stdout.write(
            f"\r{self.operation}进度: {percent:.1f}% | "
            f"块: {self.processed_chunks}/{self.total_chunks} | "
            f"大小: {format_size(self.processed_bytes)}/{format_size(self.total_size)} | "
            f"速度: {format_size(avg_speed)}/s | "
            f"剩余: {format_time(remaining_time)} | "
            f"内存: {mem_used:.1f}MB ({mem_percent}%)"
        )
        sys.stdout.flush()
    
    def complete(self):
        """完成进度显示"""
        if self.completed:
            return
        
        self.completed = True
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            speed = self.total_size / elapsed
        else:
            speed = 0
        resource_report = self.resource_monitor.report()
        
        sys.stdout.write(
            f"\r{self.operation}完成: 100% | "
            f"块: {self.total_chunks}/{self.total_chunks} | "
            f"大小: {format_size(self.total_size)} | "
            f"速度: {format_size(speed)}/s | "
            f"耗时: {format_time(elapsed)} | "
            f"峰值内存: {resource_report['memory']:.1f}MB | "
            f"峰值CPU: {resource_report['cpu_peak']:.1f}%\n"
        )
        sys.stdout.flush()
        return resource_report

def format_size(size_bytes):
    """格式化文件大小显示"""
    if size_bytes == 0:
        return "0B"
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    i = min(len(units)-1, int(math.floor(math.log(max(1, size_bytes), 1024))))
    size = round(size_bytes / (1024 ** i), 2)
    return f"{size} {units[i]}"

def format_time(seconds):
    """格式化时间显示"""
    seconds = max(0, seconds)
    if seconds < 60:
        return f"{seconds:.1f}秒"
    elif seconds < 3600:
        minutes = seconds // 60
        seconds = seconds % 60
        return f"{minutes:.0f}分{seconds:.0f}秒"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60
        return f"{hours:.0f}时{minutes:.0f}分{seconds:.0f}秒"

def get_optimal_chunk_size(file_size, encoding, compression, safe_mode):
    """根据文件大小、编码、压缩和模式计算最佳块大小"""
    # 基础块大小
    chunk_size = DEFAULT_CHUNK_SIZE
    
    # 根据文件大小调整
    if file_size > 50 * 1024 * 1024 * 1024:  # >50GB
        chunk_size = 50 * 1024 * 1024
    elif file_size > 10 * 1024 * 1024 * 1024:  # >10GB
        chunk_size = 30 * 1024 * 1024
    elif file_size > 1 * 1024 * 1024 * 1024:  # >1GB
        chunk_size = 10 * 1024 * 1024
    elif file_size > 100 * 1024 * 1024:  # >100MB
        chunk_size = 3 * 1024 * 1024
    else:  # <100MB
        chunk_size = 512 * 1024
    
    # 根据编码调整
    if encoding in ENCODING_FORMATS:
        expansion_ratio = ENCODING_FORMATS[encoding][3]
        chunk_size = int(chunk_size / expansion_ratio)
    
    # 根据压缩调整
    if compression in COMPRESSION_FORMATS:
        compression_ratio = COMPRESSION_FORMATS[compression][3]
        chunk_size = int(chunk_size / compression_ratio)
    
    # 根据编码对齐要求
    if encoding in ['base64', 'base85', 'urlsafe']:
        # 确保块大小是3的倍数
        chunk_size = chunk_size - (chunk_size % 3) or 3
    
    # 安全模式减少块大小
    if safe_mode:
        chunk_size = max(MIN_CHUNK_SIZE, min(chunk_size, 4 * 1024 * 1024))
    
    # 根据可用内存调整
    if not safe_mode:
        mem_info = psutil.virtual_memory()
        available_mem = mem_info.available * MAX_MEMORY_USAGE_PERCENT / 100
        
        # 每个块需要的内存大约是块大小的3倍（编码后数据更大）
        max_chunk_by_mem = available_mem / 3
        
        if max_chunk_by_mem > MIN_CHUNK_SIZE:
            chunk_size = min(chunk_size, max_chunk_by_mem)
    
    return min(max(chunk_size, MIN_CHUNK_SIZE), MAX_CHUNK_SIZE)

def check_memory_usage():
    """检查内存使用情况，确保安全"""
    mem = psutil.virtual_memory()
    if mem.percent > MAX_MEMORY_USAGE_PERCENT:
        logger.warning(f"内存使用过高 ({mem.percent}%)，暂停处理")
        time.sleep(1)
        return False
    return True

def optimize_system():
    """优化系统设置以提高性能"""
    try:
        # 设置文件预读大小
        if os.name == 'posix':
            # 设置文件预读大小为16MB
            os.system('blockdev --setra 32768 /dev/sda >/dev/null 2>&1')
        
        # 提高进程优先级
        if hasattr(os, 'nice'):
            os.nice(-10)
            
        # 设置进程内存优先级
        if hasattr(os, 'setpriority') and os.name == 'posix':
            os.setpriority(os.PRIO_PROCESS, os.getpid(), -10)
    except Exception as e:
        logger.debug(f"系统优化失败: {str(e)}")

def file_to_encoded(input_file, output_file=None, chunk_size=None, 
                   jobs=None, checksum=True, progress=True, encoding='base64',
                   compression='none', password=None, max_volume_size=0,
                   safe_mode=False, direct_io=False):
    """
    将任意文件转换为指定编码格式（支持大文件）
    
    :param input_file: 输入文件路径
    :param output_file: 输出文件路径（可选）
    :param chunk_size: 处理块大小（可选）
    :param jobs: 并行处理任务数（可选）
    :param checksum: 是否计算校验和
    :param progress: 是否显示进度条
    :param encoding: 编码格式
    :param compression: 压缩算法
    :param password: 加密密码（可选）
    :param max_volume_size: 分卷大小（MB），0表示不分卷
    :param safe_mode: 启用内存安全模式
    :param direct_io: 使用直接I/O（O_DIRECT）
    :return: 输出文件路径列表
    """
    try:
        # 验证输入文件
        if not os.path.isfile(input_file):
            raise FileNotFoundError(f"输入文件不存在: {input_file}")
        
        # 验证编码格式
        if encoding not in ENCODING_FORMATS:
            raise ValueError(f"不支持的编码格式: {encoding}。支持的格式: {', '.join(ENCODING_FORMATS.keys())}")
        
        # 验证压缩算法
        if compression not in COMPRESSION_FORMATS:
            raise ValueError(f"不支持的压缩算法: {compression}。支持的算法: {', '.join(COMPRESSION_FORMATS.keys())}")
        
        # 获取文件大小
        file_size = os.path.getsize(input_file)
        
        # 自动确定最佳块大小
        if chunk_size is None:
            chunk_size = get_optimal_chunk_size(file_size, encoding, compression, safe_mode)
        
        # 自动确定最佳线程数
        if jobs is None:
            jobs = max(1, min(os.cpu_count() or 1, 16))
            if safe_mode:
                jobs = min(jobs, 4)  # 安全模式下限制线程数
        
        # 计算块数量
        if file_size > 0 and chunk_size > 0:
            total_chunks = math.ceil(file_size / chunk_size)
        else:
            total_chunks = 1
        
        # 创建进度跟踪器
        progress_tracker = ProgressTracker(total_chunks, file_size, "编码") if progress else None
        
        # 初始化校验和
        file_hash = hashlib.sha256() if checksum else None
        
        # 初始化加密器
        encryptor = None
        salt = os.urandom(16)
        if password:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            encryptor = Fernet(key)
        
        # 获取编码器和压缩器
        encoder, _, _, _ = ENCODING_FORMATS.get(encoding, (None, None, "", 1.0))
        compressor, _, _, _ = COMPRESSION_FORMATS.get(compression, (None, None, "", 1.0))
        
        # 分卷处理
        volume_files = []
        volume_index = 1
        current_volume = None
        volume_writer = None
        
        # 分卷大小转换为字节
        if max_volume_size > 0:
            max_volume_bytes = max_volume_size * 1024 * 1024
            if max_volume_bytes < chunk_size:
                raise ValueError(f"分卷大小({max_volume_size}MB)必须大于块大小({chunk_size//(1024*1024)}MB)")
        else:
            max_volume_bytes = 0
        
        # 优化系统设置
        optimize_system()
        
        try:
            # 使用内存映射文件处理大文件
            if file_size > 100 * 1024 * 1024:  # >100MB
                with open(input_file, 'rb') as f:
                    # 创建内存映射
                    with mmap.mmap(f.fileno(), file_size, access=mmap.ACCESS_READ) as mm:
                        # 使用线程池并行处理
                        with ThreadPoolExecutor(max_workers=jobs) as executor:
                            futures = []
                            chunk_index = 0
                            
                            while chunk_index < total_chunks:
                                # 安全模式下检查内存使用
                                if safe_mode:
                                    while not check_memory_usage():
                                        time.sleep(0.5)
                                
                                # 计算块偏移量
                                start_pos = chunk_index * chunk_size
                                end_pos = min(start_pos + chunk_size, file_size)
                                chunk = mm[start_pos:end_pos]
                                
                                # 更新校验和
                                if file_hash:
                                    file_hash.update(chunk)
                                
                                # 提交编码任务
                                futures.append(executor.submit(
                                    process_chunk, 
                                    chunk, 
                                    chunk_index,
                                    encoder,
                                    compressor,
                                    encryptor,
                                    progress_tracker
                                ))
                                chunk_index += 1
                                
                                # 处理完成的任务
                                if len(futures) >= jobs * 2:
                                    for future in as_completed(futures[:jobs]):
                                        result = future.result()
                                        if result:
                                            encoded, index = result
                                            # 更新分卷信息
                                            current_volume, volume_writer, volume_index = write_to_volume(
                                                encoded, output_file, input_file, file_size, total_chunks, 
                                                chunk_size, encoding, compression, password, 
                                                file_hash.hexdigest() if file_hash else None,
                                                max_volume_bytes, volume_files, volume_index, 
                                                current_volume, volume_writer, progress_tracker
                                            )
                                    futures = futures[jobs:]
                            
                            # 处理剩余任务
                            for future in as_completed(futures):
                                result = future.result()
                                if result:
                                    encoded, index = result
                                    # 更新分卷信息
                                    current_volume, volume_writer, volume_index = write_to_volume(
                                        encoded, output_file, input_file, file_size, total_chunks, 
                                        chunk_size, encoding, compression, password, 
                                        file_hash.hexdigest() if file_hash else None,
                                        max_volume_bytes, volume_files, volume_index, 
                                        current_volume, volume_writer, progress_tracker
                                    )
            else:
                # 小文件使用普通I/O
                with open(input_file, 'rb') as in_file:
                    # 使用线程池并行处理
                    with ThreadPoolExecutor(max_workers=jobs) as executor:
                        futures = []
                        chunk_index = 0
                        
                        while chunk_index < total_chunks:
                            # 安全模式下检查内存使用
                            if safe_mode:
                                while not check_memory_usage():
                                    time.sleep(0.5)
                            
                            # 读取文件块
                            chunk = in_file.read(chunk_size)
                            if not chunk:
                                break
                            
                            # 更新校验和
                            if file_hash:
                                file_hash.update(chunk)
                            
                            # 提交编码任务
                            futures.append(executor.submit(
                                process_chunk, 
                                chunk, 
                                chunk_index,
                                encoder,
                                compressor,
                                encryptor,
                                progress_tracker
                            ))
                            chunk_index += 1
                            
                            # 处理完成的任务
                            if len(futures) >= jobs * 2:
                                for future in as_completed(futures[:jobs]):
                                    result = future.result()
                                    if result:
                                        encoded, index = result
                                        # 更新分卷信息
                                        current_volume, volume_writer, volume_index = write_to_volume(
                                            encoded, output_file, input_file, file_size, total_chunks, 
                                            chunk_size, encoding, compression, password, 
                                            file_hash.hexdigest() if file_hash else None,
                                            max_volume_bytes, volume_files, volume_index, 
                                            current_volume, volume_writer, progress_tracker
                                        )
                                futures = futures[jobs:]
                        
                        # 处理剩余任务
                        for future in as_completed(futures):
                            result = future.result()
                            if result:
                                encoded, index = result
                                # 更新分卷信息
                                current_volume, volume_writer, volume_index = write_to_volume(
                                    encoded, output_file, input_file, file_size, total_chunks, 
                                    chunk_size, encoding, compression, password, 
                                    file_hash.hexdigest() if file_hash else None,
                                    max_volume_bytes, volume_files, volume_index, 
                                    current_volume, volume_writer, progress_tracker
                                )
            
            # 关闭最后一个分卷
            if volume_writer:
                volume_writer.close()
                if max_volume_bytes > 0:
                    volume_files.append(current_volume)
            
            # 显示最终进度
            resource_report = None
            if progress_tracker:
                resource_report = progress_tracker.complete()
            
            logger.info(f"文件编码完成")
            logger.info(f"原始大小: {format_size(file_size)}")
            
            # 计算压缩率
            if volume_files:
                total_encoded_size = sum(os.path.getsize(f) for f in volume_files)
                if file_size > 0:
                    compression_ratio = total_encoded_size / file_size
                else:
                    compression_ratio = 0
                logger.info(f"编码后大小: {format_size(total_encoded_size)} (分卷: {len(volume_files)}个)")
                logger.info(f"压缩率: {compression_ratio:.2%}")
                logger.info(f"分卷文件: {', '.join(volume_files)}")
                return volume_files
            elif output_file:
                encoded_size = os.path.getsize(output_file)
                if file_size > 0:
                    compression_ratio = encoded_size / file_size
                else:
                    compression_ratio = 0
                logger.info(f"编码后大小: {format_size(encoded_size)}")
                logger.info(f"压缩率: {compression_ratio:.2%}")
                return [output_file]
            
            if checksum and file_hash:
                logger.info(f"SHA256: {file_hash.hexdigest()}")
            
            # 保存性能报告
            if resource_report:
                save_performance_report(input_file, resource_report, 'encode')
            
            return []
        
        except Exception as e:
            logger.error(f"编码过程中出错: {str(e)}")
            raise
    
    except Exception as e:
        logger.exception("文件编码失败")
        raise

def write_to_volume(encoded, output_file, input_file, file_size, total_chunks, 
                   chunk_size, encoding, compression, password, file_hash,
                   max_volume_bytes, volume_files, volume_index, 
                   current_volume, volume_writer, progress_tracker):
    """将编码后的块写入文件或分卷"""
    # 如果是第一个块，需要写入文件头
    if volume_writer is None:
        if max_volume_bytes > 0:
            # 分卷模式
            base_name, ext = os.path.splitext(output_file or f"encoded_{os.path.basename(input_file)}")
            current_volume = f"{base_name}.part{volume_index:03d}{ext}"
            volume_writer = open(current_volume, 'w', buffering=1024*1024)  # 1MB缓冲
            write_file_header(volume_writer, input_file, file_size, total_chunks, 
                             chunk_size, encoding, compression, password, 
                             file_hash, volume_index, total_volumes=0)
        else:
            # 单文件模式
            if output_file is None:
                output_file = f"encoded_{os.path.basename(input_file)}.{encoding}"
            volume_writer = open(output_file, 'w', buffering=1024*1024)  # 1MB缓冲
            write_file_header(volume_writer, input_file, file_size, total_chunks, 
                             chunk_size, encoding, compression, password, file_hash)
    
    # 写入数据
    volume_writer.write(encoded + '\n')
    
    # 更新进度
    if progress_tracker:
        progress_tracker.update(progress_tracker.processed_chunks + 1, len(encoded))
    
    # 检查分卷大小
    if max_volume_bytes > 0:
        current_pos = volume_writer.tell()
        if current_pos >= max_volume_bytes:
            # 关闭当前分卷
            volume_writer.close()
            volume_files.append(current_volume)
            
            # 更新总卷数
            total_volumes = volume_index + 1
            
            # 创建新分卷
            volume_index += 1
            base_name, ext = os.path.splitext(output_file or f"encoded_{os.path.basename(input_file)}")
            current_volume = f"{base_name}.part{volume_index:03d}{ext}"
            volume_writer = open(current_volume, 'w', buffering=1024*1024)
            write_file_header(volume_writer, input_file, file_size, total_chunks, 
                             chunk_size, encoding, compression, password, 
                             file_hash, volume_index, total_volumes)
    
    # 返回当前分卷信息
    return current_volume, volume_writer, volume_index

def write_file_header(file_writer, input_file, file_size, total_chunks, 
                    chunk_size, encoding, compression, password, 
                    file_hash=None, volume_index=1, total_volumes=1):
    """写入文件头信息"""
    filename = os.path.basename(input_file)
    filename_b64 = base64.b64encode(filename.encode('utf-8')).decode()
    file_writer.write(f"FILEB64:{filename_b64}\n")
    file_writer.write(f"SIZE:{file_size}\n")
    file_writer.write(f"CHUNKS:{total_chunks}\n")
    file_writer.write(f"CHUNK_SIZE:{chunk_size}\n")
    file_writer.write(f"ENCODING:{encoding}\n")
    file_writer.write(f"COMPRESSION:{compression}\n")
    if password:
        file_writer.write(f"ENCRYPTED:1\n")
    if file_hash:
        file_writer.write(f"HASH_ALGO:SHA256\n")
        file_writer.write(f"HASH:{file_hash}\n")
    if total_volumes > 1:
        file_writer.write(f"VOLUME:{volume_index}/{total_volumes}\n")
    file_writer.write(f"TIMESTAMP:{time.time()}\n")
    file_writer.write(f"PLATFORM:{platform.platform()}\n")
    file_writer.write("-----BEGIN DATA CHUNKS-----\n")
    file_writer.flush()

def process_chunk(chunk, index, encoder, compressor, encryptor, progress_tracker=None):
    """处理单个文件块（压缩+加密+编码）"""
    try:
        # 压缩
        if compressor:
            chunk = compressor(chunk)
        
        # 加密
        if encryptor:
            chunk = encryptor.encrypt(chunk)
        
        # 编码
        if callable(encoder):
            encoded = encoder(chunk)
            if isinstance(encoded, bytes):
                encoded = encoded.decode('utf-8')
        else:
            # 回退到Base64
            encoded = base64.b64encode(chunk).decode('utf-8')
        
        if progress_tracker:
            progress_tracker.update(index, len(chunk))
        
        return (encoded, index)
    except Exception as e:
        logger.error(f"处理块 {index} 时出错: {str(e)}")
        raise

def encoded_to_file(input_data, output_file=None, jobs=None, progress=True, password=None,
                  safe_mode=False, direct_io=False):
    """
    将编码文件还原为原始文件（支持大文件）
    
    :param input_data: 可以是Base64字符串或包含编码的文件路径
    :param output_file: 输出文件路径（可选）
    :param jobs: 并行处理任务数（可选）
    :param progress: 是否显示进度条
    :param password: 解密密码（可选）
    :param safe_mode: 启用内存安全模式
    :param direct_io: 使用直接I/O（O_DIRECT）
    """
    try:
        # 如果是文件路径
        if os.path.isfile(input_data):
            metadata = read_metadata(input_data)
            
            # 处理多卷文件
            if metadata.get('total_volumes', 1) > 1:
                return process_multi_volume(input_data, output_file, jobs, progress, password, safe_mode, direct_io)
            
            # 确定输出文件名
            if not output_file:
                output_file = metadata['filename']
            
            # 自动确定最佳线程数
            if jobs is None:
                jobs = max(1, min(os.cpu_count() or 1, 16))
                if safe_mode:
                    jobs = min(jobs, 4)  # 安全模式下限制线程数
                    
            # 准备进度跟踪器
            progress_tracker = ProgressTracker(
                metadata['chunks'], 
                metadata['size'], 
                "解码"
            ) if progress else None
            
            # 初始化校验和
            file_hash = hashlib.sha256() if metadata.get('hash_algo') else None
            
            # 初始化解密器
            decryptor = None
            if metadata.get('encrypted'):
                if not password:
                    password = getpass.getpass("请输入密码: ")
                # 使用固定盐值（实际应用中应从文件头获取）
                salt = b'\x00' * 16
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                decryptor = Fernet(key)
            
            # 获取解码器和解压器
            _, decoder, _, _ = ENCODING_FORMATS.get(metadata['encoding'], (None, None, "", 1.0))
            _, decompressor, _, _ = COMPRESSION_FORMATS.get(metadata['compression'], (None, None, "", 1.0))
            
            # 优化系统设置
            optimize_system()
            
            # 使用临时文件确保原子性操作
            temp_output = tempfile.NamedTemporaryFile(delete=False, prefix="tmp_", suffix=".dec")
            
            try:
                # 流式解码写入
                with open(input_data, 'r') as in_file, \
                    open(temp_output.name, 'wb') as out_file, \
                    ThreadPoolExecutor(max_workers=jobs) as executor:
                    
                    # 跳过文件头
                    while True:
                        line = in_file.readline()
                        if line.strip() == "-----BEGIN DATA CHUNKS-----":
                            break
                    
                    # 处理数据块
                    futures = []
                    chunk_index = 0
                    
                    for line in in_file:
                        # 检查结束标记
                        if line.startswith("-----END DATA CHUNKS-----"):
                            break
                        
                        # 安全模式下检查内存使用
                        if safe_mode:
                            while not check_memory_usage():
                                time.sleep(0.5)
                        
                        # 提交解码任务
                        futures.append(executor.submit(
                            decode_chunk, 
                            line.strip(), 
                            chunk_index,
                            decoder,
                            decompressor,
                            decryptor,
                            progress_tracker
                        ))
                        chunk_index += 1
                        
                        # 处理完成的任务
                        if len(futures) >= jobs * 2:
                            for future in as_completed(futures[:jobs]):
                                result = future.result()
                                if result:
                                    decoded, index = result
                                    out_file.write(decoded)
                                    if file_hash:
                                        file_hash.update(decoded)
                            futures = futures[jobs:]
                    
                    # 处理剩余任务
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            decoded, index = result
                            out_file.write(decoded)
                            if file_hash:
                                file_hash.update(decoded)
                
                # 验证文件大小
                result_size = os.path.getsize(temp_output.name)
                if result_size != metadata['size']:
                    logger.warning(f"文件大小不匹配! 原始大小: {metadata['size']}, 解码大小: {result_size}")
                
                # 验证校验和
                if file_hash and metadata.get('file_hash'):
                    actual_hash = file_hash.hexdigest()
                    if actual_hash != metadata['file_hash']:
                        logger.warning(f"校验和不匹配! 文件可能已损坏")
                        logger.warning(f"  预期: {metadata['file_hash']}")
                        logger.warning(f"  实际: {actual_hash}")
                
                # 原子性操作：重命名临时文件到最终文件
                shutil.move(temp_output.name, output_file)
                
                # 显示最终进度
                resource_report = None
                if progress_tracker:
                    resource_report = progress_tracker.complete()
                
                logger.info(f"文件解码完成: {output_file}")
                logger.info(f"文件大小: {format_size(result_size)}")
                if file_hash:
                    logger.info(f"SHA256: {file_hash.hexdigest()}")
                
                # 保存性能报告
                if resource_report:
                    save_performance_report(output_file, resource_report, 'decode')
            
            except Exception as e:
                logger.error(f"解码过程中出错: {str(e)}")
                # 清理临时文件
                if os.path.exists(temp_output.name):
                    os.remove(temp_output.name)
                raise
        
        else:
            # 小文件直接处理
            decoded = base64.b64decode(input_data)
            if not output_file:
                output_file = "decoded_file"
            with open(output_file, 'wb') as file:
                file.write(decoded)
            logger.info(f"文件已解码保存至: {output_file}")
    
    except Exception as e:
        logger.exception("文件解码失败")
        raise

def save_performance_report(file_path, resource_report, operation):
    """保存性能报告"""
    report_file = f"{file_path}.{operation}_report.json"
    try:
        with open(report_file, 'w') as f:
            json.dump({
                'operation': operation,
                'file': file_path,
                'timestamp': time.time(),
                'system': platform.platform(),
                'cpu_count': os.cpu_count(),
                'memory': psutil.virtual_memory().total,
                'report': resource_report
            }, f, indent=2)
        logger.info(f"性能报告已保存至: {report_file}")
    except Exception as e:
        logger.warning(f"无法保存性能报告: {str(e)}")

def read_metadata(file_path):
    """读取编码文件的元数据"""
    metadata = {}
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith("-----BEGIN DATA CHUNKS-----"):
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'fileb64':
                    try:
                        metadata['filename'] = base64.b64decode(value).decode('utf-8')
                    except Exception as e:
                        logger.warning(f"无法解析中文文件名: {e}")

                if key == 'file':
                    metadata['filename'] = value
                elif key == 'size':
                    try:
                        metadata['size'] = int(value)
                    except ValueError:
                        logger.warning(f"无效的文件大小: {value}")
                        metadata['size'] = 0
                elif key == 'chunks':
                    try:
                        metadata['chunks'] = int(value)
                    except ValueError:
                        logger.warning(f"无效的块数量: {value}")
                        metadata['chunks'] = 1
                elif key == 'chunk_size':
                    try:
                        metadata['chunk_size'] = int(value)
                    except ValueError:
                        logger.warning(f"无效的块大小: {value}")
                        metadata['chunk_size'] = DEFAULT_CHUNK_SIZE
                elif key == 'encoding':
                    metadata['encoding'] = value
                elif key == 'compression':
                    metadata['compression'] = value
                elif key == 'encrypted':
                    metadata['encrypted'] = value == '1'
                elif key == 'hash_algo':
                    metadata['hash_algo'] = value
                elif key == 'hash':
                    metadata['file_hash'] = value
                elif key == 'volume':
                    parts = value.split('/')
                    if len(parts) == 2:
                        try:
                            metadata['volume_index'] = int(parts[0])
                            metadata['total_volumes'] = int(parts[1])
                        except ValueError:
                            logger.warning(f"无效的分卷信息: {value}")
                elif key == 'timestamp':
                    metadata['timestamp'] = value
                elif key == 'platform':
                    metadata['platform'] = value
    
    # 验证必要元数据
    required = ['filename', 'size', 'chunks', 'chunk_size', 'encoding', 'compression']
    for key in required:
        if key not in metadata:
            logger.warning(f"元数据中缺少必要字段: {key}")
    
    return metadata

def decode_chunk(encoded, index, decoder, decompressor, decryptor, progress_tracker=None):
    """解码单个块（解码+解密+解压）"""
    try:
        # 解码
        if callable(decoder):
            decoded = decoder(encoded)
        else:
            # 尝试Base64解码作为后备
            try:
                decoded = base64.b64decode(encoded)
            except binascii.Error:
                # 尝试十六进制解码
                try:
                    decoded = binascii.unhexlify(encoded)
                except binascii.Error:
                    raise ValueError(f"无法解码块 {index}")
        
        # 解密
        if decryptor:
            try:
                decoded = decryptor.decrypt(decoded)
            except Exception as e:
                logger.error(f"解密块 {index} 失败: {str(e)}")
                raise ValueError("解密失败，可能是密码错误")
        
        # 解压
        if decompressor:
            try:
                decoded = decompressor(decoded)
            except Exception as e:
                logger.error(f"解压块 {index} 失败: {str(e)}")
                # 尝试不解压处理
                pass
        
        if progress_tracker:
            progress_tracker.update(index, len(encoded))
        
        return (decoded, index)
    except Exception as e:
        logger.error(f"处理块 {index} 时出错: {str(e)}")
        raise

def process_multi_volume(first_volume, output_file, jobs, progress, password, safe_mode, direct_io):
    """处理多卷文件"""
    # 读取第一分卷的元数据
    metadata = read_metadata(first_volume)
    
    # 确定所有分卷文件
    base_path = os.path.dirname(first_volume)
    base_name, ext = os.path.splitext(os.path.basename(first_volume))
    pattern = re.compile(r"\.part\d{3}" + re.escape(ext))
    
    volume_files = []
    for f in os.listdir(base_path):
        full_path = os.path.join(base_path, f)
        if pattern.search(f) and os.path.isfile(full_path):
            volume_files.append(full_path)
    
    volume_files.sort()
    
    if metadata.get('total_volumes', 1) > 1 and len(volume_files) != metadata['total_volumes']:
        logger.warning(f"找到的分卷数({len(volume_files)})与元数据中的分卷数({metadata['total_volumes']})不匹配")
    
    # 确定输出文件名
    if not output_file:
        output_file = metadata['filename']
    
    # 准备进度跟踪器
    progress_tracker = ProgressTracker(
        metadata['chunks'], 
        metadata['size'], 
        "解码"
    ) if progress else None
    
    # 初始化校验和
    file_hash = hashlib.sha256() if metadata.get('hash_algo') else None
    
    # 初始化解密器
    decryptor = None
    if metadata.get('encrypted'):
        if not password:
            password = getpass.getpass("请输入密码: ")
        # 使用固定盐值（实际应用中应从文件头获取）
        salt = b'\x00' * 16
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        decryptor = Fernet(key)
    
    # 获取解码器和解压器
    _, decoder, _, _ = ENCODING_FORMATS.get(metadata['encoding'], (None, None, "", 1.0))
    _, decompressor, _, _ = COMPRESSION_FORMATS.get(metadata['compression'], (None, None, "", 1.0))
    
    # 优化系统设置
    optimize_system()
    
    # 使用临时文件确保原子性操作
    temp_output = tempfile.NamedTemporaryFile(delete=False, prefix="tmp_", suffix=".dec")
    
    try:
        with open(temp_output.name, 'wb') as out_file, \
            ThreadPoolExecutor(max_workers=jobs) as executor:
            
            futures = []
            chunk_index = 0
            
            # 处理每个分卷
            for volume_file in volume_files:
                with open(volume_file, 'r') as in_file:
                    # 跳过文件头
                    while True:
                        line = in_file.readline()
                        if line.strip() == "-----BEGIN DATA CHUNKS-----":
                            break
                    
                    # 处理数据块
                    for line in in_file:
                        # 检查结束标记
                        if line.startswith("-----END DATA CHUNKS-----"):
                            break
                        
                        # 安全模式下检查内存使用
                        if safe_mode:
                            while not check_memory_usage():
                                time.sleep(0.5)
                        
                        # 提交解码任务
                        futures.append(executor.submit(
                            decode_chunk, 
                            line.strip(), 
                            chunk_index,
                            decoder,
                            decompressor,
                            decryptor,
                            progress_tracker
                        ))
                        chunk_index += 1
                        
                        # 处理完成的任务
                        if len(futures) >= jobs * 2:
                            for future in as_completed(futures[:jobs]):
                                result = future.result()
                                if result:
                                    decoded, index = result
                                    out_file.write(decoded)
                                    if file_hash:
                                        file_hash.update(decoded)
                            futures = futures[jobs:]
            
            # 处理剩余任务
            for future in as_completed(futures):
                result = future.result()
                if result:
                    decoded, index = result
                    out_file.write(decoded)
                    if file_hash:
                        file_hash.update(decoded)
        
        # 验证文件大小
        result_size = os.path.getsize(temp_output.name)
        if result_size != metadata['size']:
            logger.warning(f"文件大小不匹配! 原始大小: {metadata['size']}, 解码大小: {result_size}")
        
        # 验证校验和
        if file_hash and metadata.get('file_hash'):
            actual_hash = file_hash.hexdigest()
            if actual_hash != metadata['file_hash']:
                logger.warning(f"校验和不匹配! 文件可能已损坏")
                logger.warning(f"  预期: {metadata['file_hash']}")
                logger.warning(f"  实际: {actual_hash}")
        
        # 原子性操作：重命名临时文件到最终文件
        shutil.move(temp_output.name, output_file)
        
        # 显示最终进度
        if progress_tracker:
            progress_tracker.complete()
        
        logger.info(f"文件解码完成: {output_file}")
        logger.info(f"文件大小: {format_size(result_size)}")
        if file_hash:
            logger.info(f"SHA256: {file_hash.hexdigest()}")
    
    except Exception as e:
        logger.error(f"解码多卷文件时出错: {str(e)}")
        # 清理临时文件
        if os.path.exists(temp_output.name):
            os.remove(temp_output.name)
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='终极文件编码转换工具 (支持多编码、压缩、加密和分卷)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # 编码命令
    encode_parser = subparsers.add_parser('encode', help='文件转编码格式')
    encode_parser.add_argument('input', help='输入文件路径')
    encode_parser.add_argument('-o', '--output', help='输出文件路径（可选）')
    encode_parser.add_argument('-c', '--chunk', type=int, default=None, 
                              help=f'块大小（字节），自动确定最佳大小')
    encode_parser.add_argument('-j', '--jobs', type=int, default=None, 
                              help='并行任务数，自动确定最佳数量')
    encode_parser.add_argument('--no-checksum', action='store_true', 
                              help='不计算校验和')
    encode_parser.add_argument('--no-progress', action='store_true', 
                              help='不显示进度条')
    encode_parser.add_argument('-e', '--encoding', default='base64', 
                              choices=list(ENCODING_FORMATS.keys()),
                              help='编码格式')
    encode_parser.add_argument('-z', '--compression', default='none', 
                              choices=list(COMPRESSION_FORMATS.keys()),
                              help='压缩算法')
    encode_parser.add_argument('-p', '--password', 
                              help='加密密码（可选）')
    encode_parser.add_argument('-v', '--volume', type=int, default=0,
                              help='分卷大小（MB），0表示不分卷')
    encode_parser.add_argument('--safe-mode', action='store_true',
                              help='启用内存安全模式')
    encode_parser.add_argument('--direct-io', action='store_true',
                              help='使用直接I/O（提升大文件性能）')
    
    # 解码命令
    decode_parser = subparsers.add_parser('decode', help='编码文件转原始文件')
    decode_parser.add_argument('input', help='编码文件路径')
    decode_parser.add_argument('-o', '--output', help='输出文件路径（可选）')
    decode_parser.add_argument('-j', '--jobs', type=int, default=None, 
                              help='并行任务数，自动确定最佳数量')
    decode_parser.add_argument('--no-progress', action='store_true', 
                              help='不显示进度条')
    decode_parser.add_argument('-p', '--password', 
                              help='解密密码（可选）')
    decode_parser.add_argument('--safe-mode', action='store_true',
                              help='启用内存安全模式')
    decode_parser.add_argument('--direct-io', action='store_true',
                              help='使用直接I/O（提升大文件性能）')
    
    args = parser.parse_args()
    
    start_time = time.time()
    try:
        if args.command == 'encode':
            result_files = file_to_encoded(
                args.input, 
                args.output, 
                chunk_size=args.chunk,
                jobs=args.jobs,
                checksum=not args.no_checksum,
                progress=not args.no_progress,
                encoding=args.encoding,
                compression=args.compression,
                password=args.password,
                max_volume_size=args.volume,
                safe_mode=args.safe_mode,
                direct_io=args.direct_io
            )
            if not result_files:
                logger.error("编码失败，未生成输出文件")
        elif args.command == 'decode':
            encoded_to_file(
                args.input, 
                args.output,
                jobs=args.jobs,
                progress=not args.no_progress,
                password=args.password,
                safe_mode=args.safe_mode,
                direct_io=args.direct_io
            )
        else:
            parser.print_help()
    except Exception as e:
        logger.error(f"处理失败: {str(e)}")
        sys.exit(1)
    finally:
        total_time = time.time() - start_time
        logger.info(f"总耗时: {format_time(total_time)}")