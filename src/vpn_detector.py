import subprocess
import re
from typing import Dict, Optional, List, Union

class PineappleDetector:
    """
    A class for detecting and validating VPN connection parameters.
    
    This class provides methods to check VPN connection security and extract
    relevant network configuration details.
    """

    @staticmethod
    def detect_vpn_connection() -> Optional[Dict[str, str]]:
        """
        Detect active VPN connection and extract its parameters.
        
        Returns:
            Optional dictionary with VPN connection details or None if no VPN is detected.
        
        Raises:
            Exception: If there's an error during VPN detection.
        """
        try:
            # Check for network interfaces that might indicate a VPN
            result = subprocess.run(
                ['ip', 'addr'], 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            vpn_interfaces = [
                'tun', 'tap', 'ppp', 'wg', 'wireguard', 'openvpn', 'ipsec'
            ]
            
            for line in result.stdout.splitlines():
                for interface in vpn_interfaces:
                    if interface in line.lower():
                        # Enhanced regex to capture full interface name
                        match = re.search(r'(\d+:\s*(\w+(?:\d+)?[@\w]*)):', line)
                        state_match = re.search(r'state\s+(\w+)', line)
                        
                        if match:
                            # Extract the actual interface name from the matched group
                            interface_name = match.group(2)
                            return {
                                'interface': interface_name,
                                'state': state_match.group(1) if state_match else 'UNKNOWN'
                            }
            
            return None
        
        except subprocess.CalledProcessError as e:
            print(f"Error detecting VPN: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error in VPN detection: {e}")
            return None

    @staticmethod
    def validate_vpn_security(connection_info: Optional[Dict[str, str]]) -> List[str]:
        """
        Validate the security of a VPN connection.
        
        Args:
            connection_info: Dictionary containing VPN connection details.
        
        Returns:
            List of security recommendations or warnings.
        """
        if not connection_info:
            return ["No VPN connection detected"]
        
        recommendations = []
        
        # Check interface state
        if connection_info.get('state', '').lower() != 'up':
            recommendations.append("VPN interface is not in an active state")
        
        # Add more security checks here
        recommendations.append("Consider using strong encryption protocols")
        recommendations.append("Verify VPN provider's no-log policy")
        
        return recommendations

    @staticmethod
    def get_vpn_ip() -> Optional[str]:
        """
        Retrieve the current VPN IP address.
        
        Returns:
            VPN IP address or None if not found.
        """
        try:
            result = subprocess.run(
                ['curl', '-s', 'https://api.ipify.org'], 
                capture_output=True, 
                text=True, 
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None
        except Exception:
            return None