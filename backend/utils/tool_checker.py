#!/usr/bin/env python3
"""
Tool Checker Module
Check status of installed security tools
"""

import subprocess
import logging
from typing import Dict

logger = logging.getLogger(__name__)

class ToolChecker:
    def __init__(self):
        self.tools = {
            'sqlmap': 'sqlmap --version',
            'nmap': 'nmap --version',
            'wpscan': 'wpscan --version',
            'nikto': 'nikto -Version',
            'hydra': 'hydra -h',
            'john': 'john --version',
            'hashcat': 'hashcat --version'
        }

    def check_all_tools(self) -> Dict:
        """Check status of all tools"""
        result = {
            'tools_status': {},
            'installed_count': 0,
            'total_count': len(self.tools)
        }

        for tool_name, check_cmd in self.tools.items():
            status = self._check_tool(tool_name, check_cmd)
            result['tools_status'][tool_name] = status
            if status['installed']:
                result['installed_count'] += 1

        return result

    def _check_tool(self, tool_name: str, check_cmd: str) -> Dict:
        """Check if a specific tool is installed"""
        try:
            result = subprocess.run(
                check_cmd.split(),
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return {
                'installed': result.returncode == 0,
                'version': result.stdout.strip()[:100] if result.returncode == 0 else None,
                'error': result.stderr.strip() if result.returncode != 0 else None
            }
        
        except Exception as e:
            return {
                'installed': False,
                'version': None,
                'error': str(e)
            }