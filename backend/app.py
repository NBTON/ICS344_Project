"""
SecureChat Main Flask Application

This module sets up the Flask application with SocketIO, CORS,
and registers all routes and event handlers.
"""

import os
from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_cors import CORS

from backend.config import BackendConfig

# Initialize SocketIO without app (will be initialized in create_app)
socketio = SocketIO()


def create_app(config_class=None):
    """
    Application factory for creating Flask app instances.
    
    Args:
        config_class: Configuration class to use. Defaults to BackendConfig.
    
    Returns:
        Flask: Configured Flask application instance.
    """
    # Get the base directory for templates and static files
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_dir = os.path.join(base_dir, 'frontend', 'templates')
    static_dir = os.path.join(base_dir, 'frontend', 'static')
    
    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir
    )
    
    # Load configuration
    if config_class is None:
        config_class = BackendConfig
    app.config.from_object(config_class)
    
    # Initialize CORS
    CORS(app, origins=app.config.get('CORS_ORIGINS', '*'))
    
    # Initialize SocketIO
    socketio.init_app(
        app,
        cors_allowed_origins=app.config.get('CORS_ORIGINS', '*'),
        async_mode='eventlet'
    )
    
    # Register blueprints
    _register_blueprints(app)
    
    # Register frontend routes
    _register_frontend_routes(app)
    
    # Register WebSocket handlers
    _register_websocket_handlers()
    
    # Register error handlers
    _register_error_handlers(app)
    
    return app


def _register_blueprints(app):
    """Register Flask blueprints for API routes."""
    from backend.api.routes import api_bp
    from attack_lab.routes import attack_lab_bp
    
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(attack_lab_bp)  # Already has /api/attack-lab prefix


def _register_frontend_routes(app):
    """Register frontend page routes."""
    
    @app.route('/')
    def index():
        """Landing/login page."""
        return render_template('index.html')
    
    @app.route('/chat')
    def chat():
        """Main chat interface."""
        return render_template('chat.html')
    
    @app.route('/attack-lab')
    def attack_lab():
        """Attack Lab interface."""
        return render_template('attack_lab.html')


def _register_websocket_handlers():
    """Register WebSocket event handlers."""
    from backend.api import websocket  # noqa: F401
    # WebSocket handlers are registered via decorators in the websocket module


def _register_error_handlers(app):
    """Register error handlers for the application."""
    
    @app.errorhandler(400)
    def bad_request(error):
        return {'error': 'Bad Request', 'message': str(error)}, 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return {'error': 'Unauthorized', 'message': str(error)}, 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return {'error': 'Forbidden', 'message': str(error)}, 403
    
    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Not Found', 'message': str(error)}, 404
    
    @app.errorhandler(429)
    def rate_limited(error):
        return {'error': 'Too Many Requests', 'message': str(error)}, 429
    
    @app.errorhandler(500)
    def internal_error(error):
        return {'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}, 500


# Health check route
@socketio.on('ping')
def handle_ping():
    """Handle ping events for connection testing."""
    return 'pong'