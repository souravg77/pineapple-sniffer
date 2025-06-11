import pytest
import subprocess
from unittest.mock import patch
from src.vpn_detector import PineappleDetector

class TestPineappleDetector:
    @patch('subprocess.run')
    def test_detect_vpn_connection_with_vpn(self, mock_run):
        # Mock a scenario with a VPN interface
        mock_run.return_value.stdout = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
            "2: tun0@NONE: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 100"
        )
        mock_run.return_value.returncode = 0
        
        result = PineappleDetector.detect_vpn_connection()
        assert result is not None
        # Split and check if it matches the expected format
        assert 'tun0' in result['interface']

    @patch('subprocess.run')
    def test_detect_vpn_connection_without_vpn(self, mock_run):
        # Mock a scenario without VPN interfaces
        mock_run.return_value.stdout = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000"
        )
        mock_run.return_value.returncode = 0
        
        result = PineappleDetector.detect_vpn_connection()
        assert result is None

    def test_validate_vpn_security_with_connection(self):
        connection_info = {'interface': 'tun0', 'state': 'UP'}
        recommendations = PineappleDetector.validate_vpn_security(connection_info)
        
        assert len(recommendations) > 0
        assert "Consider using strong encryption protocols" in recommendations

    def test_validate_vpn_security_without_connection(self):
        recommendations = PineappleDetector.validate_vpn_security(None)
        
        assert recommendations == ["No VPN connection detected"]

    @patch('subprocess.run')
    def test_get_vpn_ip_success(self, mock_run):
        mock_run.return_value.stdout = "8.8.8.8"
        mock_run.return_value.returncode = 0
        
        ip = PineappleDetector.get_vpn_ip()
        assert ip == "8.8.8.8"

    @patch('subprocess.run')
    def test_get_vpn_ip_failure(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, 'curl')
        
        ip = PineappleDetector.get_vpn_ip()
        assert ip is None