#!/usr/bin/env python3
"""
Intercepteur SSL pour capturer les données Dofus en clair
Utilise mitmproxy pour décrypter le trafic HTTPS
"""

import json
import time
from datetime import datetime
from mitmproxy import http, ctx
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from mitmproxy.tools.web.master import WebMaster


class DofusSSLInterceptor:
    def __init__(self, output_file="dofus_decrypted.json"):
        self.output_file = output_file
        self.packet_count = 0

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercepte les requêtes HTTP/HTTPS"""
        if self.is_dofus_traffic(flow):
            self.log_request(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        """Intercepte les réponses HTTP/HTTPS"""
        if self.is_dofus_traffic(flow):
            self.log_response(flow)

    def is_dofus_traffic(self, flow: http.HTTPFlow) -> bool:
        """Détermine si c'est du trafic Dofus"""
        host = flow.request.pretty_host.lower()

        # Domaines Dofus connus
        dofus_domains = [
            'dofus.com',
            'ankama.com',
            'ankama-games.com',
            'dofus2.fr',
            'staticns.ankama.com'
        ]

        return any(domain in host for domain in dofus_domains)

    def log_request(self, flow: http.HTTPFlow):
        """Log une requête"""
        self.packet_count += 1

        data = {
            'id': self.packet_count,
            'timestamp': datetime.now().isoformat(),
            'type': 'request',
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'host': flow.request.pretty_host,
            'headers': dict(flow.request.headers),
            'content_type': flow.request.headers.get('content-type', ''),
            'content_length': len(flow.request.content) if flow.request.content else 0
        }

        # Contenu si c'est du texte/JSON
        if flow.request.content and self.is_text_content(flow.request.headers.get('content-type', '')):
            try:
                data['content'] = flow.request.content.decode('utf-8')
            except:
                data['content_hex'] = flow.request.content.hex()

        self.write_to_file(data)
        print(f"📤 REQ {self.packet_count}: {flow.request.method} {flow.request.pretty_url}")

    def log_response(self, flow: http.HTTPFlow):
        """Log une réponse"""
        self.packet_count += 1

        data = {
            'id': self.packet_count,
            'timestamp': datetime.now().isoformat(),
            'type': 'response',
            'status_code': flow.response.status_code,
            'url': flow.request.pretty_url,
            'host': flow.request.pretty_host,
            'headers': dict(flow.response.headers),
            'content_type': flow.response.headers.get('content-type', ''),
            'content_length': len(flow.response.content) if flow.response.content else 0
        }

        # Contenu si c'est du texte/JSON
        if flow.response.content and self.is_text_content(flow.response.headers.get('content-type', '')):
            try:
                data['content'] = flow.response.content.decode('utf-8')

                # Essayer de parser comme JSON
                if 'json' in data['content_type'].lower():
                    try:
                        data['parsed_json'] = json.loads(data['content'])
                    except:
                        pass

            except:
                data['content_hex'] = flow.response.content.hex()

        self.write_to_file(data)
        print(f"📥 RESP {self.packet_count}: {flow.response.status_code} {flow.request.pretty_url}")

    def is_text_content(self, content_type: str) -> bool:
        """Vérifie si le contenu est du texte"""
        text_types = ['text/', 'application/json', 'application/xml', 'application/x-www-form-urlencoded']
        return any(t in content_type.lower() for t in text_types)

    def write_to_file(self, data):
        """Écrit dans le fichier de sortie"""
        with open(self.output_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(data, ensure_ascii=False) + '\n')


def run_ssl_interceptor(port=8080, web_port=8081):
    """Lance l'intercepteur SSL"""
    print(f"🚀 Démarrage de l'intercepteur SSL Dofus")
    print(f"📡 Proxy: localhost:{port}")
    print(f"🌐 Interface web: http://localhost:{web_port}")
    print(f"📝 Sortie: dofus_decrypted.json")
    print()
    print("📋 Configuration Dofus:")
    print("   1. Va dans les paramètres réseau de ton Mac")
    print("   2. Configure le proxy HTTP/HTTPS vers localhost:8080")
    print("   3. Installe le certificat mitmproxy (http://mitm.it/)")
    print("   4. Lance Dofus")
    print()

    try:
        # Options mitmproxy (version moderne)
        opts = Options(
            listen_port=port,
            ssl_insecure=True,
            confdir="~/.mitmproxy"
        )

        # Créer le master avec interface web
        master = WebMaster(opts)
        master.addons.add(DofusSSLInterceptor())

        # Démarrer sur le port web spécifié
        master.options.web_port = web_port

        master.run()
    except Exception as e:
        print(f"❌ Erreur configuration mitmproxy: {e}")
        print("🔄 Essai avec configuration simplifiée...")

        # Fallback vers mode console
        try:
            run_console_interceptor_simple(port)
        except Exception as e2:
            print(f"❌ Erreur fallback: {e2}")
    except KeyboardInterrupt:
        print("\n⏹️  Arrêt de l'intercepteur")


def run_console_interceptor_simple(port=8080):
    """Version console simplifiée compatible"""
    print("🚀 Intercepteur SSL console (mode simplifié)")
    print(f"   Configure ton proxy vers localhost:{port}")

    try:
        opts = Options(
            listen_port=port,
            ssl_insecure=True
        )

        master = DumpMaster(opts)
        master.addons.add(DofusSSLInterceptor())
        master.run()
    except Exception as e:
        print(f"❌ Erreur mode console: {e}")

# Script alternatif pour mode console simple
def run_console_interceptor():
    """Version console simple"""
    print("🚀 Intercepteur SSL console")
    print("   Configure ton proxy vers localhost:8080")

    try:
        opts = Options(
            listen_port=8080,
            ssl_insecure=True
        )

        master = DumpMaster(opts)
        master.addons.add(DofusSSLInterceptor())
        master.run()
    except Exception as e:
        print(f"❌ Erreur intercepteur: {e}")
        print("💡 Essayez: pip install --upgrade mitmproxy")
    except KeyboardInterrupt:
        print("\n⏹️  Arrêt")


if __name__ == "__main__":
    import sys

    # Installation des dépendances
    print("📦 Assure-toi d'avoir installé mitmproxy:")
    print("   pip install mitmproxy")
    print()

    if len(sys.argv) > 1 and sys.argv[1] == "--console":
        run_console_interceptor()
    else:
        run_ssl_interceptor()