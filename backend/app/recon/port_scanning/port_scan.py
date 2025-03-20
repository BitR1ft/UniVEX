"""
Naabu Port Scanner Wrapper

This module provides a Python wrapper around Naabu for fast port scanning.
Supports both SYN and CONNECT scans with configurable rate limiting and threading.
"""
import asyncio
import json
import logging
import shutil
from typing import List, Optional
from datetime import datetime

from .schemas import PortInfo, IPPortScan, ScanType

logger = logging.getLogger(__name__)


class PortScanner:
    """
    Naabu port scanner wrapper for active port scanning
    """
    
    def __init__(
        self,
        scan_type: ScanType = ScanType.SYN,
        top_ports: int = 1000,
        custom_ports: Optional[List[int]] = None,
        port_range: Optional[str] = None,
        rate_limit: int = 1000,
        threads: int = 25,
        timeout: int = 10,
    ):
        """
        Initialize the port scanner
        
        Args:
            scan_type: Type of scan (SYN or CONNECT)
            top_ports: Number of top ports to scan (default: 1000)
            custom_ports: List of specific ports to scan
            port_range: Port range string (e.g., "1-65535")
            rate_limit: Packets per second (default: 1000)
            threads: Number of threads (default: 25)
            timeout: Timeout in seconds (default: 10)
        """
        self.scan_type = scan_type
        self.top_ports = top_ports
        self.custom_ports = custom_ports
        self.port_range = port_range
        self.rate_limit = rate_limit
        self.threads = threads
        self.timeout = timeout
        
        # Check if naabu is installed
        if not self._check_naabu_installed():
            logger.warning("Naabu is not installed. Port scanning will not work.")
    
    def _check_naabu_installed(self) -> bool:
        """Check if Naabu is installed and available"""
        return shutil.which("naabu") is not None
    
    def _build_naabu_command(self, target: str) -> List[str]:
        """
        Build Naabu command with specified options
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            List of command arguments
        """
        cmd = ["naabu", "-host", target, "-json"]
        
        # Scan type
        if self.scan_type == ScanType.SYN:
            cmd.append("-s")
            cmd.append("s")
        else:
            cmd.append("-s")
            cmd.append("c")
        
        # Port selection
        if self.custom_ports:
            cmd.extend(["-p", ",".join(map(str, self.custom_ports))])
        elif self.port_range:
            cmd.extend(["-p", self.port_range])
        else:
            cmd.extend(["-top-ports", str(self.top_ports)])
        
        # Performance options
        cmd.extend(["-rate", str(self.rate_limit)])
        cmd.extend(["-c", str(self.threads)])
        cmd.extend(["-timeout", str(self.timeout)])
        
        # Additional options
        cmd.append("-silent")  # Suppress banner
        cmd.append("-no-color")  # No color output
        
        return cmd
    
    async def scan_host(self, target: str) -> IPPortScan:
        """
        Scan a single host for open ports
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            IPPortScan object with results
        """
        start_time = datetime.now()
        
        if not self._check_naabu_installed():
            logger.error("Naabu is not installed")
            return IPPortScan(
                ip=target,
                ports=[],
                scan_duration=0,
                timestamp=start_time.isoformat()
            )
        
        try:
            cmd = self._build_naabu_command(target)
            logger.info(f"Scanning {target} with command: {' '.join(cmd)}")
            
            # Run Naabu asynchronously
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Naabu scan failed for {target}: {stderr.decode()}")
                return IPPortScan(
                    ip=target,
                    ports=[],
                    scan_duration=(datetime.now() - start_time).total_seconds(),
                    timestamp=start_time.isoformat()
                )
            
            # Parse Naabu JSON output
            ports = self._parse_naabu_output(stdout.decode(), target)
            
            scan_duration = (datetime.now() - start_time).total_seconds()
            
            return IPPortScan(
                ip=target,
                ports=ports,
                scan_duration=scan_duration,
                timestamp=start_time.isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error scanning {target}: {str(e)}")
            return IPPortScan(
                ip=target,
                ports=[],
                scan_duration=(datetime.now() - start_time).total_seconds(),
                timestamp=start_time.isoformat()
            )
    
    def _parse_naabu_output(self, output: str, target: str) -> List[PortInfo]:
        """
        Parse Naabu JSON output
        
        Args:
            output: JSON output from Naabu
            target: Target IP/hostname
            
        Returns:
            List of PortInfo objects
        """
        ports = []
        
        for line in output.strip().split('\n'):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                # Naabu JSON format: {"host":"IP","port":PORT}
                if 'port' in data:
                    port_info = PortInfo(
                        port=int(data['port']),
                        protocol=data.get('protocol', 'tcp'),
                        state="open",
                        source="naabu"
                    )
                    ports.append(port_info)
                    
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse JSON line: {line}")
            except Exception as e:
                logger.error(f"Error parsing port data: {str(e)}")
        
        logger.info(f"Found {len(ports)} open ports on {target}")
        return ports
    
    async def scan_multiple_hosts(
        self,
        targets: List[str],
        parallel: bool = True,
        max_concurrent: int = 10
    ) -> List[IPPortScan]:
        """
        Scan multiple hosts
        
        Args:
            targets: List of IP addresses or hostnames
            parallel: Whether to scan in parallel
            max_concurrent: Maximum concurrent scans
            
        Returns:
            List of IPPortScan results
        """
        if not parallel:
            results = []
            for target in targets:
                result = await self.scan_host(target)
                results.append(result)
            return results
        
        # Parallel scanning with semaphore
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(target: str):
            async with semaphore:
                return await self.scan_host(target)
        
        tasks = [scan_with_semaphore(target) for target in targets]
        results = await asyncio.gather(*tasks)
        
        return results
