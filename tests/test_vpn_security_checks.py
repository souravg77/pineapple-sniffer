import pytest
from src.vpn_security_checks import VPNSecurityChecker

class TestVPNSecurityChecker:
    def setup_method(self):
        self.checker = VPNSecurityChecker()
    
    def test_protocol_security_secure(self):
        secure_protocols = ['WireGuard', 'OpenVPN', 'IKEv2']
        for protocol in secure_protocols:
            result = VPNSecurityChecker.check_protocol_security(protocol)
            assert result['is_secure'] is True
            assert result['is_weak'] is False
    
    def test_protocol_security_weak(self):
        weak_protocols = ['PPTP', 'L2TP']
        for protocol in weak_protocols:
            result = VPNSecurityChecker.check_protocol_security(protocol)
            assert result['is_secure'] is False
            assert result['is_weak'] is True
    
    def test_encryption_strength_analysis(self):
        test_cases = [
            ('128-bit', 1, False),
            ('256-bit', 3, True),
            ('512-bit', 4, True),
            ('1024-bit', 5, True)
        ]
        
        for encryption, expected_score, expected_recommended in test_cases:
            result = VPNSecurityChecker.analyze_encryption_strength(encryption)
            assert result['strength_score'] == expected_score
            assert result['is_recommended'] == expected_recommended
    
    def test_comprehensive_vpn_security_check(self):
        test_cases = [
            ('WireGuard', '256-bit', 3),
            ('OpenVPN', '128-bit', 2),
            ('PPTP', '128-bit', 1)
        ]
        
        for protocol, encryption, expected_rating in test_cases:
            result = self.checker.comprehensive_vpn_security_check(protocol, encryption)
            assert result['overall_security_rating'] == expected_rating