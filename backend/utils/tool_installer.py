#!/usr/bin/env python3
"""
Tool Installer Module
Automated installation of security tools
"""

import os
import subprocess
import sys
import platform
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class ToolInstaller:
    def __init__(self):
        self.system = platform.system().lower()
        self.tools = {
            'sqlmap': {
                'description': 'Automatic SQL injection and database takeover tool',
                'install_cmd': self._get_sqlmap_install_cmd(),
                'check_cmd': 'sqlmap --version',
                'required': True
            },
            'nmap': {
                'description': 'Network discovery and security auditing',
                'install_cmd': self._get_nmap_install_cmd(),
                'check_cmd': 'nmap --version',
                'required': True
            },
            'wpscan': {
                'description': 'WordPress vulnerability scanner',
                'install_cmd': self._get_wpscan_install_cmd(),
                'check_cmd': 'wpscan --version',
                'required': False
            },
            'nikto': {
                'description': 'Web server scanner',
                'install_cmd': self._get_nikto_install_cmd(),
                'check_cmd': 'nikto -Version',
                'required': False
            },
            'dirb': {
                'description': 'Web content scanner',
                'install_cmd': self._get_dirb_install_cmd(),
                'check_cmd': 'dirb',
                'required': False
            },
            'hydra': {
                'description': 'Password cracking tool',
                'install_cmd': self._get_hydra_install_cmd(),
                'check_cmd': 'hydra -h',
                'required': False
            },
            'john': {
                'description': 'John the Ripper password cracker',
                'install_cmd': self._get_john_install_cmd(),
                'check_cmd': 'john --version',
                'required': False
            },
            'hashcat': {
                'description': 'Advanced password recovery',
                'install_cmd': self._get_hashcat_install_cmd(),
                'check_cmd': 'hashcat --version',
                'required': False
            }
        }

    def install_tools(self, tool_list: List[str] = None) -> Dict:
        """Install specified tools or all tools"""
        if tool_list is None or 'all' in tool_list:
            tool_list = list(self.tools.keys())
        
        results = {
            'installed': [],
            'failed': [],
            'already_installed': [],
            'errors': []
        }
        
        logger.info(f"Installing tools: {', '.join(tool_list)}")
        
        for tool_name in tool_list:
            if tool_name not in self.tools:
                results['errors'].append(f"Unknown tool: {tool_name}")
                continue
            
            tool_info = self.tools[tool_name]
            
            # Check if already installed
            if self._check_tool_installed(tool_name):
                results['already_installed'].append(tool_name)
                logger.info(f"{tool_name} is already installed")
                continue
            
            # Install the tool
            try:
                logger.info(f"Installing {tool_name}: {tool_info['description']}")
                
                if isinstance(tool_info['install_cmd'], list):
                    for cmd in tool_info['install_cmd']:
                        self._run_command(cmd)
                else:
                    self._run_command(tool_info['install_cmd'])
                
                # Verify installation
                if self._check_tool_installed(tool_name):
                    results['installed'].append(tool_name)
                    logger.info(f"Successfully installed {tool_name}")
                else:
                    results['failed'].append(tool_name)
                    logger.error(f"Installation verification failed for {tool_name}")
            
            except Exception as e:
                results['failed'].append(tool_name)
                results['errors'].append(f"Failed to install {tool_name}: {str(e)}")
                logger.error(f"Failed to install {tool_name}: {str(e)}")
        
        return results

    def _check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed"""
        try:
            check_cmd = self.tools[tool_name]['check_cmd']
            result = subprocess.run(
                check_cmd.split(),
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def _run_command(self, command: str) -> str:
        """Run a shell command"""
        logger.debug(f"Running command: {command}")
        
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout
        )
        
        if result.returncode != 0:
            raise Exception(f"Command failed: {command}\nError: {result.stderr}")
        
        return result.stdout

    def _get_sqlmap_install_cmd(self) -> str:
        """Get SQLMap installation command"""
        if self.system == 'linux':
            return "apt-get update && apt-get install -y sqlmap"
        elif self.system == 'darwin':  # macOS
            return "brew install sqlmap"
        else:
            return "pip install sqlmap-python"

    def _get_nmap_install_cmd(self) -> str:
        """Get Nmap installation command"""
        if self.system == 'linux':
            return "apt-get update && apt-get install -y nmap"
        elif self.system == 'darwin':
            return "brew install nmap"
        else:
            return "echo 'Please install Nmap manually from https://nmap.org/download.html'"

    def _get_wpscan_install_cmd(self) -> List[str]:
        """Get WPScan installation commands"""
        if self.system in ['linux', 'darwin']:
            return [
                "gem install wpscan",
                "wpscan --update"
            ]
        else:
            return ["echo 'WPScan requires Ruby. Please install manually.'"]

    def _get_nikto_install_cmd(self) -> str:
        """Get Nikto installation command"""
        if self.system == 'linux':
            return "apt-get update && apt-get install -y nikto"
        elif self.system == 'darwin':
            return "brew install nikto"
        else:
            return "echo 'Please install Nikto manually'"

    def _get_dirb_install_cmd(self) -> str:
        """Get DIRB installation command"""
        if self.system == 'linux':
            return "apt-get update && apt-get install -y dirb"
        elif self.system == 'darwin':
            return "brew install dirb"
        else:
            return "echo 'Please install DIRB manually'"

    def _get_hydra_install_cmd(self) -> str:
        """Get Hydra installation command"""
        if self.system == 'linux':
            return "apt-get update && apt-get install -y hydra"
        elif self.system == 'darwin':
            return "brew install hydra"
        else:
            return "echo 'Please install Hydra manually'"

    def _get_john_install_cmd(self) -> str:
        """Get John the Ripper installation command"""
        if self.system == 'linux':
            return "apt-get update && apt-get install -y john"
        elif self.system == 'darwin':
            return "brew install john"
        else:
            return "echo 'Please install John the Ripper manually'"

    def _get_hashcat_install_cmd(self) -> str:
        """Get Hashcat installation command"""
        if self.system == 'linux':
            return "apt-get update && apt-get install -y hashcat"
        elif self.system == 'darwin':
            return "brew install hashcat"
        else:
            return "echo 'Please install Hashcat manually'"