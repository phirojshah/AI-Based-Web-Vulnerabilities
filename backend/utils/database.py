#!/usr/bin/env python3
"""
Database Module
SQLite database for storing scan results
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class ScanDatabase:
    def __init__(self, db_path: str = 'security_scanner.db'):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize the database with required tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create scan_results table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT NOT NULL,
                        scan_type TEXT NOT NULL,
                        results TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'completed'
                    )
                ''')
                
                # Create exploit_results table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS exploit_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT NOT NULL,
                        exploit_type TEXT NOT NULL,
                        results TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        success BOOLEAN DEFAULT FALSE
                    )
                ''')
                
                # Create targets table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS targets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT UNIQUE NOT NULL,
                        first_scan DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_scan DATETIME DEFAULT CURRENT_TIMESTAMP,
                        scan_count INTEGER DEFAULT 0
                    )
                ''')
                
                conn.commit()
                logger.info("Database initialized successfully")
        
        except Exception as e:
            logger.error(f"Database initialization failed: {str(e)}")

    def store_scan_result(self, target: str, scan_type: str, results: Dict) -> int:
        """Store scan results in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Insert scan result
                cursor.execute('''
                    INSERT INTO scan_results (target, scan_type, results)
                    VALUES (?, ?, ?)
                ''', (target, scan_type, json.dumps(results)))
                
                result_id = cursor.lastrowid
                
                # Update or insert target
                cursor.execute('''
                    INSERT OR REPLACE INTO targets (url, first_scan, last_scan, scan_count)
                    VALUES (?, 
                            COALESCE((SELECT first_scan FROM targets WHERE url = ?), CURRENT_TIMESTAMP),
                            CURRENT_TIMESTAMP,
                            COALESCE((SELECT scan_count FROM targets WHERE url = ?), 0) + 1)
                ''', (target, target, target))
                
                conn.commit()
                logger.info(f"Stored scan result for {target} (type: {scan_type})")
                return result_id
        
        except Exception as e:
            logger.error(f"Failed to store scan result: {str(e)}")
            return -1

    def store_exploit_result(self, target: str, exploit_type: str, results: Dict) -> int:
        """Store exploit results in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                success = results.get('exploitation_successful', False)
                
                cursor.execute('''
                    INSERT INTO exploit_results (target, exploit_type, results, success)
                    VALUES (?, ?, ?, ?)
                ''', (target, exploit_type, json.dumps(results), success))
                
                result_id = cursor.lastrowid
                conn.commit()
                
                logger.info(f"Stored exploit result for {target} (type: {exploit_type}, success: {success})")
                return result_id
        
        except Exception as e:
            logger.error(f"Failed to store exploit result: {str(e)}")
            return -1

    def get_scan_results(self, target: str = None, scan_type: str = None, limit: int = 100) -> List[Dict]:
        """Retrieve scan results from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM scan_results WHERE 1=1"
                params = []
                
                if target:
                    query += " AND target = ?"
                    params.append(target)
                
                if scan_type:
                    query += " AND scan_type = ?"
                    params.append(scan_type)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                results = []
                for row in rows:
                    results.append({
                        'id': row[0],
                        'target': row[1],
                        'scan_type': row[2],
                        'results': json.loads(row[3]),
                        'timestamp': row[4],
                        'status': row[5]
                    })
                
                return results
        
        except Exception as e:
            logger.error(f"Failed to retrieve scan results: {str(e)}")
            return []

    def get_target_summary(self, target: str) -> Optional[Dict]:
        """Get summary information for a target"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get target info
                cursor.execute("SELECT * FROM targets WHERE url = ?", (target,))
                target_row = cursor.fetchone()
                
                if not target_row:
                    return None
                
                # Get scan counts by type
                cursor.execute('''
                    SELECT scan_type, COUNT(*) 
                    FROM scan_results 
                    WHERE target = ? 
                    GROUP BY scan_type
                ''', (target,))
                scan_counts = dict(cursor.fetchall())
                
                # Get exploit counts
                cursor.execute('''
                    SELECT exploit_type, COUNT(*), SUM(success)
                    FROM exploit_results 
                    WHERE target = ? 
                    GROUP BY exploit_type
                ''', (target,))
                exploit_data = cursor.fetchall()
                
                exploit_counts = {}
                for exploit_type, total, successful in exploit_data:
                    exploit_counts[exploit_type] = {
                        'total': total,
                        'successful': successful or 0
                    }
                
                return {
                    'url': target_row[1],
                    'first_scan': target_row[2],
                    'last_scan': target_row[3],
                    'total_scans': target_row[4],
                    'scan_counts': scan_counts,
                    'exploit_counts': exploit_counts
                }
        
        except Exception as e:
            logger.error(f"Failed to get target summary: {str(e)}")
            return None

    def cleanup_old_results(self, days: int = 30):
        """Clean up old scan results"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    DELETE FROM scan_results 
                    WHERE timestamp < datetime('now', '-{} days')
                '''.format(days))
                
                cursor.execute('''
                    DELETE FROM exploit_results 
                    WHERE timestamp < datetime('now', '-{} days')
                '''.format(days))
                
                deleted_scans = cursor.rowcount
                conn.commit()
                
                logger.info(f"Cleaned up {deleted_scans} old results")
        
        except Exception as e:
            logger.error(f"Failed to cleanup old results: {str(e)}")