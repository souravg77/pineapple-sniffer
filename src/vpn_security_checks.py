from typing import Dict, List, Optional, Any
import re

class VPNSecurityChecker:
    """
    A comprehensive VPN security checking utility.
    
    Provides methods to analyze VPN encryption strength 
    and protocol security characteristics.
    """
    
    SECURE_PROTOCOLS = ['WireGuard', 'OpenVPN', 'IKEv2']
    WEAK_PROTOCOLS = ['PPTP', 'L2TP']
    
    @staticmethod
    def check_protocol_security(protocol: str) -> Dict[str, bool]:
        """
        Evaluate the security of a given VPN protocol.
        
        Args:
            protocol (str): The VPN protocol to check
        
        Returns:
            Dict[str, bool]: Security assessment of the protocol
        """
        return {
            'is_secure': protocol in VPNSecurityChecker.SECURE_PROTOCOLS,
            'is_weak': protocol in VPNSecurityChecker.WEAK_PROTOCOLS
        }
    
    @staticmethod
    def analyze_encryption_strength(encryption: str) -> Dict[str, int]:
        """
        Assess the strength of VPN encryption.
        
        Args:
            encryption (str): Encryption method/key length
        
        Returns:
            Dict[str, int]: Encryption strength metrics
        """
        # Basic encryption strength heuristics
        strength_map = {
            '128-bit': 1,   # Considered weak
            '256-bit': 3,   # Strong
            '512-bit': 4,   # Very Strong
            '1024-bit': 5   # Extremely Strong
        }
        
        # Search for bit strength in the encryption string
        match = re.search(r'(\d+)-bit', encryption)
        if match:
            bit_strength = f"{match.group(1)}-bit"
            return {
                'strength_score': strength_map.get(bit_strength, 0),
                'is_recommended': bit_strength in ['256-bit', '512-bit', '1024-bit']
            }
        
        return {'strength_score': 0, 'is_recommended': False}
    
    def comprehensive_vpn_security_check(
        self, 
        protocol: str, 
        encryption: str
    ) -> Dict[str, Any]:
        """
        Perform a comprehensive security check on VPN configuration.
        
        Args:
            protocol (str): VPN protocol
            encryption (str): Encryption method
        
        Returns:
            Dict[str, Any]: Comprehensive security assessment
        """
        protocol_security = self.check_protocol_security(protocol)
        encryption_strength = self.analyze_encryption_strength(encryption)
        
        return {
            'protocol': {
                'name': protocol,
                'is_secure': protocol_security['is_secure'],
                'is_weak': protocol_security['is_weak']
            },
            'encryption': {
                'method': encryption,
                'strength_score': encryption_strength['strength_score'],
                'is_recommended': encryption_strength['is_recommended']
            },
            'overall_security_rating': (
                3 if protocol_security['is_secure'] and encryption_strength['is_recommended']
                else 2 if protocol_security['is_secure']
                else 1
            )
        }