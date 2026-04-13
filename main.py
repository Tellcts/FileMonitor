#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件监控告警工具 - File Integrity Monitor & Alert System
适用于 Linux 环境，基于哈希校验监测文件异常变更，检测到篡改时自动通过 SMTP 发送邮件告警
"""

import hashlib
import smtplib
import json
import os
import sys
import time
import logging
import argparse
import signal
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from datetime import datetime, timezone, timedelta
from typing import Optional
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler

# ===================== 常量 =====================
VERSION = "1.0.0"  # 版本号
DEFAULT_CONFIG_FILE = "monitor_config.json"  # 默认配置文件
DEFAULT_HASH_DB_FILE = "file_hashes.json"  # 默认文件哈希数据库
DEFAULT_LOG_FILE = "file_monitor.log"  # 默认日志文件
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB         # 日志文件最大容量
BACKUP_COUNT = 5  # 备份日志个数
DEFAULT_SCAN_INTERVAL = 60  # 默认扫描间隔


# ===================== 配置数据类 =====================
@dataclass
class SMTPConfig:
    smtp_server: str = "smtp.qq.com"
    smtp_port: int = 465
    use_ssl: bool = True
    use_tls: bool = False
    username: str = ""
    password: str = ""
    sender: str = ""
    receivers: list = field(default_factory=list)
    mail_subject_prefix: str = "[文件监控告息]"


@dataclass
class MonitorConfig:
    watch_files: list = field(default_factory=list)
    watch_dirs: list = field(default_factory=list)
    exclude_patterns: list = field(default_factory=list)
    hash_algorithm: str = "sha256"
    scan_interval: int = DEFAULT_SCAN_INTERVAL
    max_retries: int = 3
    retry_delay: int = 5
    log_level: str = "INFO"
    log_file: str = DEFAULT_LOG_FILE
    hash_db_file: str = DEFAULT_HASH_DB_FILE
    smtp: SMTPConfig = field(default_factory=SMTPConfig)


# ===================== 配置管理器 =====================
class ConfigManager:
    """管理配置的加载、保存与验证"""

    def __init__(self, config_path: str = DEFAULT_CONFIG_FILE):
        self.config_path = config_path
        self.config = MonitorConfig()

    def load(self) -> MonitorConfig:
        if not os.path.exists(self.config_path):
            self._save_default_template()
            return self.config
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            smtp_data = data.get("smtp", {})
            smtp_config = SMTPConfig(
                smtp_server=smtp_data.get("smtp_server", "smtp.qq.com"),
                smtp_port=smtp_data.get("smtp_port", 465),
                use_ssl=smtp_data.get("use_ssl", True),
                use_tls=smtp_data.get("use_tls", False),
                username=smtp_data.get("username", ""),
                password=smtp_data.get("password", ""),
                sender=smtp_data.get("sender", ""),
                receivers=smtp_data.get("receivers", []),
                mail_subject_prefix=smtp_data.get(
                    "mail_subject_prefix", "[文件监控告息]"
                ),
            )
            self.config = MonitorConfig(
                watch_files=data.get("watch_files", []),
                watch_dirs=data.get("watch_dirs", []),
                exclude_patterns=data.get("exclude_patterns", []),
                hash_algorithm=data.get("hash_algorithm", "sha256"),
                scan_interval=data.get("scan_interval", DEFAULT_SCAN_INTERVAL),
                max_retries=data.get("max_retries", 3),
                retry_delay=data.get("retry_delay", 5),
                log_level=data.get("log_level", "INFO"),
                log_file=data.get("log_file", DEFAULT_LOG_FILE),
                hash_db_file=data.get("hash_db_file", DEFAULT_HASH_DB_FILE),
                smtp=smtp_config,
            )
            self._validate()
            return self.config
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            raise ValueError(f"配置文件格式错误: {e}")

    def _validate(self):
        algo = self.config.hash_algorithm.lower()
        if algo not in ("md5", "sha256", "both"):
            raise ValueError(f"不支持的哈希算法: {algo}，可选: md5, sha256, both")
        if self.config.scan_interval < 5:
            self.config.scan_interval = 5
        if not self.config.watch_files and not self.config.watch_dirs:
            raise ValueError(
                "请至少配置一个监控文件(watch_files)或监控目录(watch_dirs)"
            )
        if self.config.smtp.receivers and not self.config.smtp.sender:
            self.config.smtp.sender = self.config.smtp.username

    def _save_default_template(self):
        template = {
            "watch_files": ["/etc/passwd", "/etc/hosts"],
            "watch_dirs": ["/etc/nginx", "/etc/ssh"],
            "exclude_patterns": ["*.log", "*.tmp", "*.swp", ".git/*", "__pycache__/*"],
            "hash_algorithm": "sha256",
            "scan_interval": 60,
            "max_retries": 3,
            "retry_delay": 5,
            "log_level": "INFO",
            "log_file": DEFAULT_LOG_FILE,
            "hash_db_file": DEFAULT_HASH_DB_FILE,
            "smtp": {
                "smtp_server": "smtp.qq.com",
                "smtp_port": 465,
                "use_ssl": True,
                "use_tls": False,
                "username": "your_email@qq.com",
                "password": "your_smtp_auth_code",
                "sender": "your_email@qq.com",
                "receivers": ["admin@example.com"],
                "mail_subject_prefix": "[文件监控告息]",
            },
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(template, f, indent=4, ensure_ascii=False)
        print(f"[提示] 已生成默认配置模板: {self.config_path}")
        print("[提示] 请编辑配置文件后重新运行程序。")


# ===================== 哈希计算工具 =====================
class HashCalculator:
    """文件哈希计算，支持 MD5 / SHA256 / 双算法，大文件分块读取"""

    CHUNK_SIZE = 65536  # 64KB

    @staticmethod
    def compute_hash(filepath: str, algorithm: str = "sha256") -> dict:
        result = {"size": 0, "mtime": ""}
        if not os.path.isfile(filepath):
            return result
        try:
            stat = os.stat(filepath)
            result["size"] = stat.st_size
            result["mtime"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
        except OSError:
            return result

        algo_lower = algorithm.lower()
        md5_hash = hashlib.md5() if algo_lower in ("md5", "both") else None
        sha256_hash = hashlib.sha256() if algo_lower in ("sha256", "both") else None

        try:
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(HashCalculator.CHUNK_SIZE)
                    if not chunk:
                        break
                    if md5_hash:
                        md5_hash.update(chunk)
                    if sha256_hash:
                        sha256_hash.update(chunk)
        except (IOError, OSError):
            return result

        if md5_hash:
            result["md5"] = md5_hash.hexdigest()
        if sha256_hash:
            result["sha256"] = sha256_hash.hexdigest()
        return result

    @staticmethod
    def is_hash_changed(old_record: dict, new_record: dict) -> bool:
        for key in ("md5", "sha256"):
            if key in old_record and key in new_record:
                if old_record[key] != new_record[key]:
                    return True
        return False


# ===================== 哈希数据库 =====================
class HashDatabase:
    """文件哈希数据库，JSON 持久化"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.records: dict = {}
        self._load()

    def _load(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    self.records = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.records = {}
                backup_path = f"{self.db_path}.bak.{int(time.time())}"
                try:
                    os.rename(self.db_path, backup_path)
                except OSError:
                    pass

    def save(self):
        try:
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(self.records, f, indent=2, ensure_ascii=False)
        except IOError as e:
            raise IOError(f"无法保存哈希数据库: {e}")

    def get(self, filepath: str) -> Optional[dict]:
        return self.records.get(filepath)

    def update(self, filepath: str, record: dict):
        self.records[filepath] = record

    def remove(self, filepath: str):
        self.records.pop(filepath, None)

    def get_all_files(self) -> list:
        return list(self.records.keys())

    @property
    def count(self) -> int:
        return len(self.records)


# ===================== 邮件告警模块 =====================
class EmailAlerter:
    """基于 SMTP 协议的邮件告警发送器，支持 SSL/TLS 与自动重试"""

    def __init__(
        self, smtp_config: SMTPConfig, max_retries: int = 3, retry_delay: int = 5
    ):
        self.config = smtp_config
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.logger = logging.getLogger("file_monitor.alerter")

    def send_alert(self, subject: str, body: str, html: bool = False) -> bool:
        if not self.config.receivers:
            self.logger.warning("未配置邮件接收人，跳过发送")
            return False
        if not self.config.username or not self.config.password:
            self.logger.warning("未配置 SMTP 认证信息，跳过发送")
            return False

        for attempt in range(1, self.max_retries + 1):
            try:
                return self._do_send(subject, body, html)
            except Exception as e:
                self.logger.error(f"邮件发送失败 (第{attempt}次尝试): {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    self.logger.error(
                        f"邮件发送已达到最大重试次数({self.max_retries})，放弃发送"
                    )
        return False

    def _do_send(self, subject: str, body: str, html: bool = False) -> bool:
        msg = MIMEMultipart("alternative")
        # msg["From"] = Header(self.config.sender or self.config.username, "utf-8")
        # msg["To"] = Header(", ".join(self.config.receivers), "utf-8")
        # msg["Subject"] = Header(f"{self.config.mail_subject_prefix} {subject}", "utf-8")
        from email.utils import formataddr

        sender_email = self.config.sender or self.config.username
        msg["From"] = formataddr(("文件监控告警", sender_email))
        msg["To"] = ", ".join(self.config.receivers)
        msg["Subject"] = f"{self.config.mail_subject_prefix} {subject}"

        msg["Date"] = datetime.now(timezone(timedelta(hours=8))).strftime(
            "%a, %d %b %Y %H:%M:%S +0800"
        )
        msg.attach(MIMEText(body, "html" if html else "plain", "utf-8"))

        if self.config.use_ssl:
            server = smtplib.SMTP_SSL(
                self.config.smtp_server, self.config.smtp_port, timeout=30
            )
        else:
            server = smtplib.SMTP(
                self.config.smtp_server, self.config.smtp_port, timeout=30
            )
        try:
            if self.config.use_tls and not self.config.use_ssl:
                server.starttls()
            server.login(self.config.username, self.config.password)
            server.sendmail(
                self.config.sender or self.config.username,
                self.config.receivers,
                msg.as_string(),
            )
            self.logger.info(f"告警邮件发送成功 -> {self.config.receivers}")
            return True
        finally:
            try:
                server.quit()
            except Exception:
                pass

    def build_change_alert_html(self, changes: list) -> str:
        """构建文件变更告警 HTML 邮件正文"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = ""
        for change in changes:
            file_path = change.get("file", "未知")
            change_type = change.get("type", "unknown")
            details = change.get("details", "-")
            badge_class = {
                "modified": "badge-modified",
                "deleted": "badge-deleted",
                "created": "badge-created",
            }.get(change_type, "badge-modified")
            type_label = {
                "modified": "文件被修改",
                "deleted": "文件被删除",
                "created": "新增文件",
            }.get(change_type, change_type)
            rows += f"""
                <tr>
                    <td style="padding:8px 12px;border-bottom:1px solid #e0e0e0;font-size:13px;
                        word-break:break-all;font-family:monospace;">{file_path}</td>
                    <td style="padding:8px 12px;border-bottom:1px solid #e0e0e0;font-size:13px;">
                        <span style="display:inline-block;padding:2px 10px;border-radius:12px;
                        font-size:12px;font-weight:bold;color:#fff;
                        background:{'#ff9800' if change_type=='modified' else '#d32f2f' if change_type=='deleted' else '#2196f3'};">
                        {type_label}</span></td>
                    <td style="padding:8px 12px;border-bottom:1px solid #e0e0e0;font-size:13px;">{details}</td>
                </tr>"""

        return f"""<html><body style="font-family:'Microsoft YaHei',Arial,sans-serif;background:#f5f5f5;padding:20px;margin:0;">
<div style="max-width:700px;margin:0 auto;background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.1);overflow:hidden;">
    <div style="background:linear-gradient(135deg,#d32f2f,#b71c1c);color:#fff;padding:20px 30px;text-align:center;">
        <h1 style="margin:0;font-size:22px;">&#9888; 文件完整性变更告警</h1>
        <div style="margin-top:8px;font-size:13px;opacity:0.9;">检测时间: {now}</div>
    </div>
    <div style="padding:25px 30px;">
        <div style="background:#fff3e0;border-left:4px solid #ff9800;padding:12px 16px;
            margin-bottom:20px;border-radius:4px;">
            <strong style="color:#e65100;">检测到 {len(changes)} 个文件发生变更，请立即检查！</strong>
        </div>
        <table style="width:100%;border-collapse:collapse;margin-top:10px;">
            <tr>
                <th style="background:#37474f;color:#fff;padding:10px 12px;text-align:left;font-size:13px;">文件路径</th>
                <th style="background:#37474f;color:#fff;padding:10px 12px;text-align:left;font-size:13px;">变更类型</th>
                <th style="background:#37474f;color:#fff;padding:10px 12px;text-align:left;font-size:13px;">详细信息</th>
            </tr>
            {rows}
        </table>
    </div>
    <div style="text-align:center;padding:15px;color:#999;font-size:12px;border-top:1px solid #eee;">
        文件监控告警系统 v{VERSION} | 本邮件由系统自动发送，请勿直接回复
    </div>
</div></body></html>"""


# ===================== 文件扫描器 =====================
class FileScanner:
    """文件扫描器，递归收集监控目标，支持排除规则"""

    DEFAULT_EXCLUDE = {
        "*.log",
        "*.tmp",
        "*.swp",
        "*.bak",
        "*.pid",
        "*.sock",
        ".git",
        "__pycache__",
        ".DS_Store",
        "Thumbs.db",
        "node_modules",
        ".svn",
        "*.pyc",
    }

    def __init__(self, config: MonitorConfig):
        self.config = config
        self.exclude = set(self.DEFAULT_EXCLUDE)
        self.exclude.update(p.strip().lower() for p in config.exclude_patterns)
        self.logger = logging.getLogger("file_monitor.scanner")

    def get_all_target_files(self) -> set:
        files = set()
        for f in self.config.watch_files:
            if os.path.isfile(f):
                files.add(os.path.abspath(f))
            else:
                self.logger.warning(f"监控文件不存在: {f}")
        for directory in self.config.watch_dirs:
            if os.path.isdir(directory):
                dir_files = self._scan_directory(directory)
                files.update(dir_files)
                self.logger.info(
                    f"目录 {directory} 扫描完成，发现 {len(dir_files)} 个文件"
                )
            else:
                self.logger.warning(f"监控目录不存在: {directory}")
        return files

    def _scan_directory(self, directory: str) -> set:
        files = set()
        try:
            for root, dirs, filenames in os.walk(directory):
                dirs[:] = [d for d in dirs if not self._is_excluded(d, is_dir=True)]
                for filename in filenames:
                    if not self._is_excluded(filename):
                        files.add(os.path.abspath(os.path.join(root, filename)))
        except PermissionError as e:
            self.logger.error(f"无权限访问目录 {directory}: {e}")
        except OSError as e:
            self.logger.error(f"扫描目录异常 {directory}: {e}")
        return files

    def _is_excluded(self, name: str, is_dir: bool = False) -> bool:
        name_lower = name.lower()
        for pattern in self.exclude:
            if pattern.startswith("*") and pattern.endswith("*"):
                if pattern[1:-1] in name_lower:
                    return True
            elif pattern.startswith("*"):
                if name_lower.endswith(pattern[1:]):
                    return True
            elif pattern.endswith("*"):
                if name_lower.startswith(pattern[:-1]):
                    return True
            elif name_lower == pattern:
                return True
        return False


# ===================== 核心监控引擎 =====================
class FileMonitorEngine:
    """文件监控核心引擎：基线初始化 → 周期扫描 → 变更检测 → 邮件告警"""

    def __init__(self, config: MonitorConfig):
        self.config = config
        self.logger = logging.getLogger("file_monitor.engine")
        self.hash_db = HashDatabase(config.hash_db_file)
        self.scanner = FileScanner(config)
        self.alerter = EmailAlerter(config.smtp, config.max_retries, config.retry_delay)
        self._stop_event = False
        self._scan_count = 0

    def start(self, once: bool = False):
        self.logger.info("=" * 60)
        self.logger.info("文件监控告警系统启动")
        self.logger.info(f"版本: {VERSION}")
        self.logger.info(f"哈希算法: {self.config.hash_algorithm}")
        self.logger.info(f"扫描间隔: {self.config.scan_interval} 秒")
        self.logger.info(f"哈希数据库: {self.config.hash_db_file}")
        self.logger.info("=" * 60)

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self._initialize_baseline()
        if once:
            self.logger.info("单次扫描模式完成，退出。")
            return

        try:
            while not self._stop_event:
                time.sleep(self.config.scan_interval)
                if self._stop_event:
                    break
                self._scan_and_check()
        except KeyboardInterrupt:
            self.logger.info("接收到中断信号，正在停止监控...")
        finally:
            self._shutdown()

    def _initialize_baseline(self):
        """首次扫描，为所有监控文件建立哈希基线"""
        self.logger.info("[基线初始化] 正在首次扫描所有监控文件...")
        target_files = self.scanner.get_all_target_files()
        self.logger.info(f"[基线初始化] 发现 {len(target_files)} 个文件需要记录")
        for filepath in sorted(target_files):
            try:
                record = HashCalculator.compute_hash(
                    filepath, self.config.hash_algorithm
                )
                self.hash_db.update(filepath, record)
                self.logger.debug(f"  记录基线: {filepath}")
            except Exception as e:
                self.logger.error(f"  计算哈希失败: {filepath} -> {e}")
        self.hash_db.save()
        self.logger.info(
            f"[基线初始化] 完成，已记录 {self.hash_db.count} 个文件的哈希基线"
        )
        self._scan_count = 1

    def _scan_and_check(self):
        """执行一轮扫描：检测文件修改、新增、删除"""
        self._scan_count += 1
        self.logger.info(f"--- 第 {self._scan_count} 轮扫描开始 ---")
        changes = []
        target_files = self.scanner.get_all_target_files()

        # 检测修改与新增
        for filepath in sorted(target_files):
            # try:
            #     new_record = HashCalculator.compute_hash(
            #         filepath, self.config.hash_algorithm
            #     )
            #     old_record = self.hash_db.get(filepath)
            try:
                # 【优化点：mtime 预检，跳过未修改的文件】
                old_record = self.hash_db.get(filepath)
                if old_record is not None:
                    try:
                        stat_info = os.stat(filepath)
                        # 对比到纳秒级（Linux 支持 st_mtime_ns）
                        if (
                            old_record.get("mtime")
                            == datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                        ):
                            continue  # 修改时间没变，直接跳过，不算哈希
                    except OSError:
                        pass

                new_record = HashCalculator.compute_hash(
                    filepath, self.config.hash_algorithm
                )

                if old_record is None:
                    # 新增文件
                    changes.append(
                        {
                            "file": filepath,
                            "type": "created",
                            "details": f"文件大小: {new_record.get('size', 0)} 字节, "
                            f"修改时间: {new_record.get('mtime', '未知')}",
                        }
                    )
                    self.hash_db.update(filepath, new_record)
                    self.logger.warning(f"[新增文件] {filepath}")

                elif HashCalculator.is_hash_changed(old_record, new_record):
                    # 文件被篡改
                    detail_parts = []
                    for hash_key in ("md5", "sha256"):
                        if hash_key in old_record and hash_key in new_record:
                            if old_record[hash_key] != new_record[hash_key]:
                                detail_parts.append(
                                    f"{hash_key.upper()}: {old_record[hash_key][:12]}... -> "
                                    f"{new_record[hash_key][:12]}..."
                                )
                    old_size = old_record.get("size", 0)
                    new_size = new_record.get("size", 0)
                    detail_parts.append(
                        f"大小: {old_size} -> {new_size} 字节 ({new_size - old_size:+d})"
                    )
                    detail_parts.append(
                        f"修改时间: {old_record.get('mtime', '未知')} -> {new_record.get('mtime', '未知')}"
                    )
                    changes.append(
                        {
                            "file": filepath,
                            "type": "modified",
                            "details": "<br>".join(detail_parts),
                        }
                    )
                    self.hash_db.update(filepath, new_record)
                    self.logger.warning(
                        f"[文件篡改] {filepath} - {'; '.join(detail_parts)}"
                    )
            except Exception as e:
                self.logger.error(f"检查文件异常 {filepath}: {e}")

        # 检测删除
        for filepath in list(self.hash_db.get_all_files()):
            if filepath not in target_files:
                old_record = self.hash_db.get(filepath)
                changes.append(
                    {
                        "file": filepath,
                        "type": "deleted",
                        "details": f"最后记录大小: {old_record.get('size', '未知')} 字节, "
                        f"最后修改时间: {old_record.get('mtime', '未知')}",
                    }
                )
                self.hash_db.remove(filepath)
                self.logger.warning(f"[文件删除] {filepath}")

        if changes:
            self.hash_db.save()
            self._handle_alerts(changes)
            self.logger.warning(f"本轮扫描共检测到 {len(changes)} 个文件变更！")
        else:
            self.logger.info("本轮扫描完成，所有文件完好")

    def _handle_alerts(self, changes: list):
        """汇总变更并发送告警邮件"""
        self.logger.info(f"正在发送告警邮件 (共 {len(changes)} 条变更)...")
        subject = f"检测到 {len(changes)} 个文件变更"
        summary_lines = []
        for c in changes:
            type_label = {"modified": "修改", "deleted": "删除", "created": "新增"}.get(
                c["type"], c["type"]
            )
            summary_lines.append(f"  [{type_label}] {c['file']}")
        plain_body = (
            f"文件完整性监控告警\n"
            f"检测时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"变更数量: {len(changes)}\n\n变更详情:\n"
            + "\n".join(summary_lines)
            + "\n\n请及时检查！"
        )
        html_body = self.alerter.build_change_alert_html(changes)
        success = self.alerter.send_alert(subject, html_body, html=True)
        if not success:
            self.logger.warning("HTML邮件发送失败，尝试纯文本格式...")
            self.alerter.send_alert(subject, plain_body, html=False)

    def _signal_handler(self, signum, frame):
        sig_name = signal.Signals(signum).name
        self.logger.info(f"接收到信号 {sig_name}，准备停止...")
        self._stop_event = True

    def _shutdown(self):
        self.logger.info("文件监控告警系统已停止")
        self.logger.info("=" * 60)


# ===================== 日志管理器 =====================
class LogManager:
    """日志管理：控制台 + 滚动文件日志"""

    @staticmethod
    def setup(config: MonitorConfig):
        log_level = getattr(logging, config.log_level.upper(), logging.INFO)
        root_logger = logging.getLogger("file_monitor")
        root_logger.setLevel(log_level)
        root_logger.handlers.clear()

        # 控制台
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        root_logger.addHandler(console_handler)

        # 文件（滚动切割）
        try:
            file_handler = RotatingFileHandler(
                config.log_file,
                maxBytes=MAX_LOG_SIZE,
                backupCount=BACKUP_COUNT,
                encoding="utf-8",
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s] [%(levelname)s] [%(name)s] [%(funcName)s:%(lineno)d] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            root_logger.addHandler(file_handler)
        except IOError as e:
            root_logger.warning(
                f"无法创建日志文件 {config.log_file}: {e}，仅使用控制台日志"
            )


# ===================== 命令行工具函数 =====================
def cmd_hash(config: MonitorConfig, files: list):
    """计算并显示文件哈希值"""
    if not files:
        print("请指定要计算哈希的文件路径")
        return
    for filepath in files:
        if not os.path.isfile(filepath):
            print(f"文件不存在: {filepath}")
            continue
        record = HashCalculator.compute_hash(filepath, config.hash_algorithm)
        print(f"文件: {filepath}")
        print(f"  大小: {record['size']} 字节")
        print(f"  修改时间: {record['mtime']}")
        if "md5" in record:
            print(f"  MD5:    {record['md5']}")
        if "sha256" in record:
            print(f"  SHA256: {record['sha256']}")
        print()


def cmd_init(config: MonitorConfig):
    """仅初始化哈希基线，不进入监控"""
    LogManager.setup(config)
    engine = FileMonitorEngine(config)
    engine._initialize_baseline()
    print(f"基线初始化完成，已记录 {engine.hash_db.count} 个文件。")


def cmd_status(config: MonitorConfig):
    """显示当前监控状态"""
    db = HashDatabase(config.hash_db_file)
    print(f"哈希数据库: {config.hash_db_file}")
    print(f"已记录文件数: {db.count}")
    print(f"监控算法: {config.hash_algorithm}")
    print(f"监控文件: {len(config.watch_files)} 个")
    print(f"监控目录: {len(config.watch_dirs)} 个")
    print()
    if db.count > 0:
        print("已记录的文件列表:")
        for filepath in sorted(db.get_all_files()):
            record = db.get(filepath)
            hash_info = ""
            if "sha256" in record:
                hash_info = f"SHA256:{record['sha256'][:16]}..."
            elif "md5" in record:
                hash_info = f"MD5:{record['md5'][:12]}..."
            print(f"  {filepath}  [{hash_info}]")


def cmd_verify(config: MonitorConfig):
    """手动验证一次，不发送邮件"""
    LogManager.setup(config)
    engine = FileMonitorEngine(config)
    target_files = engine.scanner.get_all_target_files()
    print(f"正在验证 {len(target_files)} 个文件...")
    changed, missing = 0, 0
    for filepath in sorted(target_files):
        old_record = engine.hash_db.get(filepath)
        if old_record is None:
            print(f"  [新增] {filepath}")
            continue
        if not os.path.isfile(filepath):
            print(f"  [缺失] {filepath}")
            missing += 1
            continue
        new_record = HashCalculator.compute_hash(filepath, config.hash_algorithm)
        if HashCalculator.is_hash_changed(old_record, new_record):
            print(f"  [变更] {filepath}")
            changed += 1
        else:
            print(f"  [正常] {filepath}")
    print(f"\n验证完成: {changed} 个变更, {missing} 个缺失")


def cmd_list(config: MonitorConfig):
    """列出所有监控目标文件"""
    LogManager.setup(config)
    scanner = FileScanner(config)
    target_files = scanner.get_all_target_files()
    print(f"当前监控目标文件共 {len(target_files)} 个:\n")
    for f in sorted(target_files):
        print(f"  {f}")


# ===================== 主入口 =====================
def main():
    parser = argparse.ArgumentParser(
        description="文件监控告警工具 - File Integrity Monitor & Alert System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
使用示例:
  python3 file_monitor.py                          # 启动监控 (首次运行生成配置模板)
  python3 file_monitor.py -c /etc/fim/config.json  # 指定配置文件启动监控
  python3 file_monitor.py --init                   # 仅初始化哈希基线
  python3 file_monitor.py --hash /etc/passwd       # 计算指定文件哈希值
  python3 file_monitor.py --status                 # 查看监控状态
  python3 file_monitor.py --verify                 # 手动验证文件完整性
  python3 file_monitor.py --list                   # 列出所有监控目标文件
  python3 file_monitor.py --once                   # 单次扫描模式（不进入循环）

Linux 部署建议:
  1. pip3 install 无需额外依赖，全部使用标准库
  2. chmod +x file_monitor.py
  3. nohup python3 file_monitor.py -c /etc/fim/config.json > /dev/null 2>&1 &
  4. 或配置 systemd 服务实现开机自启
        """,
    )
    parser.add_argument(
        "-c",
        "--config",
        default=DEFAULT_CONFIG_FILE,
        help=f"配置文件路径 (默认: {DEFAULT_CONFIG_FILE})",
    )
    parser.add_argument("--init", action="store_true", help="仅初始化哈希基线")
    parser.add_argument(
        "--hash", nargs="+", metavar="FILE", help="计算指定文件的哈希值"
    )
    parser.add_argument("--status", action="store_true", help="显示监控状态")
    parser.add_argument("--verify", action="store_true", help="手动验证文件完整性")
    parser.add_argument("--list", action="store_true", help="列出所有监控目标文件")
    parser.add_argument("--once", action="store_true", help="单次扫描模式")
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {VERSION}"
    )
    args = parser.parse_args()

    try:
        config_manager = ConfigManager(args.config)
        config = config_manager.load()
    except ValueError as e:
        print(f"配置错误: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"配置文件不存在: {args.config}", file=sys.stderr)
        sys.exit(1)

    if args.hash:
        cmd_hash(config, args.hash)
    elif args.status:
        cmd_status(config)
    elif args.verify:
        cmd_verify(config)
    elif args.list:
        cmd_list(config)
    elif args.init:
        cmd_init(config)
    else:
        LogManager.setup(config)
        engine = FileMonitorEngine(config)
        engine.start(once=args.once)


if __name__ == "__main__":
    main()
