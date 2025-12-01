#!/usr/bin/env python3
"""
SecureChat Application Entry Point

This script starts the SecureChat Flask application with SocketIO support.

Usage:
    python run.py [--host HOST] [--port PORT] [--debug]

Environment variables:
    FLASK_ENV: development, production, or testing
    HOST: Server host (default: 0.0.0.0)
    PORT: Server port (default: 5000)
    DEBUG: Enable debug mode (default: False)
"""

import os
import sys
import argparse
import logging

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend import create_app, socketio
from backend.config import get_config


def setup_logging(debug: bool = False):
    """Configure logging for the application."""
    level = logging.DEBUG if debug else logging.INFO
    format_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    logging.basicConfig(
        level=level,
        format=format_str,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Reduce noise from some libraries
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('engineio').setLevel(logging.WARNING)
    logging.getLogger('socketio').setLevel(logging.WARNING)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Start the SecureChat server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run.py                     # Run with defaults
    python run.py --debug             # Run in debug mode
    python run.py --port 8080         # Run on port 8080
    python run.py --host 127.0.0.1    # Run on localhost only
        """
    )
    
    parser.add_argument(
        '--host',
        type=str,
        default=os.environ.get('HOST', '0.0.0.0'),
        help='Host to bind to (default: 0.0.0.0)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=int(os.environ.get('PORT', 5000)),
        help='Port to bind to (default: 5000)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        default=os.environ.get('DEBUG', 'False').lower() in ('true', '1', 'yes'),
        help='Enable debug mode'
    )
    
    parser.add_argument(
        '--no-reload',
        action='store_true',
        help='Disable auto-reload in debug mode'
    )
    
    return parser.parse_args()


def print_banner(host: str, port: int, debug: bool):
    """Print startup banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗           ║
║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝           ║
║   ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗             ║
║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝             ║
║   ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗           ║
║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝           ║
║                                                               ║
║    ██████╗██╗  ██╗ █████╗ ████████╗                           ║
║   ██╔════╝██║  ██║██╔══██╗╚══██╔══╝                           ║
║   ██║     ███████║███████║   ██║                              ║
║   ██║     ██╔══██║██╔══██║   ██║                              ║
║   ╚██████╗██║  ██║██║  ██║   ██║                              ║
║    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝                              ║
║                                                               ║
║           End-to-End Encrypted Messaging                      ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)
    print(f"  🔒 SecureChat Server Starting...")
    print(f"  📍 Address: http://{host}:{port}")
    print(f"  🔧 Debug Mode: {'ON' if debug else 'OFF'}")
    print(f"  🌐 API Endpoint: http://{host}:{port}/api")
    print(f"  📡 WebSocket: ws://{host}:{port}")
    print()
    print("  Security Features:")
    print("    • AES-256-GCM message encryption")
    print("    • RSA-2048 key exchange (OAEP)")
    print("    • RSA-PSS digital signatures")
    print("    • Replay attack protection")
    print("    • Rate limiting (DoS protection)")
    print()
    print("  Press Ctrl+C to stop the server")
    print("=" * 65)
    print()


def main():
    """Main entry point."""
    args = parse_args()
    
    # Setup logging
    setup_logging(debug=args.debug)
    logger = logging.getLogger(__name__)
    
    # Print banner
    print_banner(args.host, args.port, args.debug)
    
    try:
        # Create the Flask application
        config_class = get_config()
        app = create_app(config_class)
        
        # Set debug mode
        app.debug = args.debug
        
        logger.info(f"Starting SecureChat server on {args.host}:{args.port}")
        
        # Run with SocketIO
        socketio.run(
            app,
            host=args.host,
            port=args.port,
            debug=args.debug,
            use_reloader=args.debug and not args.no_reload,
            log_output=args.debug
        )
        
    except KeyboardInterrupt:
        print("\n")
        logger.info("Server stopped by user")
        print("👋 Goodbye!")
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()