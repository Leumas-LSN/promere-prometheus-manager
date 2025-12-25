#!/usr/bin/env python3
"""
[MCP Context] Application Startup Script
=========================================
Purpose: Initialize the application with SSL certificate generation
Security: Ensures HTTPS is enforced for all connections
"""

import os
import sys
import ssl
import logging
from waitress import serve
from ssl_utils import generate_self_signed_cert
from app import app

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main startup routine"""
    logger.info("Starting Promere Central...")

    # Generate SSL certificates if they don't exist
    cert_path, key_path = generate_self_signed_cert(
        cert_dir="certs",
        cert_file="cert.pem",
        key_file="key.pem",
        validity_days=365
    )

    if not cert_path or not key_path:
        logger.error("Failed to generate or load SSL certificates")
        sys.exit(1)

    # Prepare SSL context
    logger.info("Configuring SSL context...")

    # Check if we're running in development mode (allows HTTP fallback)
    use_https = os.getenv("USE_HTTPS", "true").lower() == "true"
    port = int(os.getenv("PORT", "8091"))
    http_port = int(os.getenv("HTTP_PORT", "8090"))
    host = os.getenv("HOST", "0.0.0.0")

    if use_https:
        # --- HTTP to HTTPS Redirector ---
        # Since we cannot serve HTTP and HTTPS on the same port, we run a separate
        # HTTP server on HTTP_PORT that redirects to the HTTPS PORT.
        from flask import Flask, request, redirect
        from threading import Thread
        
        redirect_app = Flask("redirector")
        
        @redirect_app.route('/', defaults={'path': ''})
        @redirect_app.route('/<path:path>')
        def https_redirect(path):
            # Replace http:// with https:// and update the port
            new_url = request.url.replace('http://', 'https://', 1)
            # Naive port replacement: replace :8090 with :8091
            if f":{http_port}" in new_url:
                new_url = new_url.replace(f":{http_port}", f":{port}")
            return redirect(new_url, code=301)

        def run_redirector():
            logger.info(f"Starting HTTP->HTTPS redirector on {host}:{http_port}")
            serve(redirect_app, host=host, port=http_port, threads=2)

        # Start redirector in background thread
        t = Thread(target=run_redirector, daemon=True)
        t.start()
        
        # --- Main HTTPS Server ---
        logger.info(f"Starting HTTPS server on {host}:{port}")
        logger.warning("For production, use a reverse proxy (nginx/traefik) with SSL termination")

        # Use Flask's built-in SSL context for development
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)

        # Run with Flask's development server (SSL enabled)
        app.run(
            host=host,
            port=port,
            ssl_context=context,
            threaded=True
        )
    else:
        # HTTP mode (not recommended)
        logger.warning("HTTPS disabled - running in HTTP mode (NOT RECOMMENDED FOR PRODUCTION)")
        serve(app, host=host, port=port, threads=4)

if __name__ == "__main__":
    main()
