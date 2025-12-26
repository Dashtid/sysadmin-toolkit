#!/usr/bin/env bash
# Docker Lab Environment Setup Script
# Sets up a comprehensive Docker development environment
# Run as user with docker group membership

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOCKER_COMPOSE_DIR="$HOME/docker-lab"
PORTAINER_DATA_DIR="$HOME/docker-lab/portainer-data"
TRAEFIK_DATA_DIR="$HOME/docker-lab/traefik-data"

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check Docker installation
check_docker() {
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please run headless-server-setup.sh first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running or user lacks permissions."
        error "Make sure Docker is running and user is in docker group."
        exit 1
    fi
    
    log "[+] Docker is available"
}

# Create directory structure
create_directories() {
    log "[i] Creating lab directory structure..."
    
    mkdir -p "$DOCKER_COMPOSE_DIR"
    mkdir -p "$PORTAINER_DATA_DIR"
    mkdir -p "$TRAEFIK_DATA_DIR"
    mkdir -p "$DOCKER_COMPOSE_DIR/databases"
    mkdir -p "$DOCKER_COMPOSE_DIR/web-servers"
    mkdir -p "$DOCKER_COMPOSE_DIR/development"
    mkdir -p "$DOCKER_COMPOSE_DIR/monitoring"
    mkdir -p "$DOCKER_COMPOSE_DIR/networks"
    
    log "[+] Directory structure created"
}

# Create Docker networks
create_networks() {
    log "[i] Creating Docker networks..."
    
    # Create development network
    docker network create dev-network --driver bridge --subnet=172.20.0.0/16 2>/dev/null || true
    
    # Create monitoring network
    docker network create monitoring-network --driver bridge --subnet=172.21.0.0/16 2>/dev/null || true
    
    # Create database network
    docker network create db-network --driver bridge --subnet=172.22.0.0/16 2>/dev/null || true
    
    log "[+] Docker networks created"
}

# Setup Portainer for container management
setup_portainer() {
    log "[i] Setting up Portainer..."
    
    cat > "$DOCKER_COMPOSE_DIR/portainer.yml" << 'EOF'
version: '3.8'

services:
  portainer:
    image: portainer/portainer-ce:latest
    container_name: portainer
    restart: unless-stopped
    ports:
      - "9000:9000"
      - "9443:9443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - portainer_data:/data
    networks:
      - monitoring-network

volumes:
  portainer_data:
    external: false

networks:
  monitoring-network:
    external: true
EOF
    
    # Start Portainer
    cd "$DOCKER_COMPOSE_DIR"
    docker-compose -f portainer.yml up -d
    
    log "[+] Portainer started on port 9000"
}

# Setup development databases
setup_databases() {
    log "[i] Setting up development databases..."
    
    cat > "$DOCKER_COMPOSE_DIR/databases/databases.yml" << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: dev-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: devdb
      POSTGRES_USER: devuser
      POSTGRES_PASSWORD: devpass123
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - db-network

  mysql:
    image: mysql:8.0
    container_name: dev-mysql
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: rootpass123
      MYSQL_DATABASE: devdb
      MYSQL_USER: devuser
      MYSQL_PASSWORD: devpass123
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql
    networks:
      - db-network

  redis:
    image: redis:7-alpine
    container_name: dev-redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - db-network

  mongodb:
    image: mongo:6
    container_name: dev-mongodb
    restart: unless-stopped
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: adminpass123
    ports:
      - "27017:27017"
    volumes:
      - mongodb_data:/data/db
    networks:
      - db-network

volumes:
  postgres_data:
  mysql_data:
  redis_data:
  mongodb_data:

networks:
  db-network:
    external: true
EOF
    
    log "[+] Database services configured"
}

# Setup web servers and reverse proxy
setup_web_servers() {
    log "[i] Setting up web servers..."
    
    cat > "$DOCKER_COMPOSE_DIR/web-servers/nginx.yml" << 'EOF'
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    container_name: dev-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./html:/usr/share/nginx/html:ro
    networks:
      - dev-network

networks:
  dev-network:
    external: true
EOF

    # Create basic nginx config
    cat > "$DOCKER_COMPOSE_DIR/web-servers/nginx.conf" << 'EOF'
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    
    sendfile        on;
    keepalive_timeout  65;
    
    server {
        listen       80;
        server_name  localhost;
        
        location / {
            root   /usr/share/nginx/html;
            index  index.html index.htm;
        }
        
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   /usr/share/nginx/html;
        }
    }
}
EOF

    # Create sample HTML
    mkdir -p "$DOCKER_COMPOSE_DIR/web-servers/html"
    cat > "$DOCKER_COMPOSE_DIR/web-servers/html/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Docker Lab Environment</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .service { background: #f4f4f4; padding: 20px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>[i] Docker Lab Environment</h1>
        <p>Welcome to your Docker development environment!</p>
        
        <div class="service">
            <h3>[i] Portainer</h3>
            <p>Container management interface</p>
            <a href="http://localhost:9000" target="_blank">http://localhost:9000</a>
        </div>
        
        <div class="service">
            <h3>[i] Databases</h3>
            <ul>
                <li>PostgreSQL: localhost:5432 (devuser/devpass123)</li>
                <li>MySQL: localhost:3306 (devuser/devpass123)</li>
                <li>Redis: localhost:6379</li>
                <li>MongoDB: localhost:27017 (admin/adminpass123)</li>
            </ul>
        </div>
        
        <div class="service">
            <h3>[i] Development Tools</h3>
            <p>Various development containers and tools available</p>
        </div>
    </div>
</body>
</html>
EOF
    
    log "[+] Web servers configured"
}

# Setup development containers
setup_dev_containers() {
    log "[i] Setting up development containers..."
    
    cat > "$DOCKER_COMPOSE_DIR/development/dev-tools.yml" << 'EOF'
version: '3.8'

services:
  python-dev:
    image: python:3.11-slim
    container_name: python-dev
    restart: unless-stopped
    working_dir: /workspace
    volumes:
      - ./python-workspace:/workspace
    command: tail -f /dev/null
    networks:
      - dev-network

  node-dev:
    image: node:18-alpine
    container_name: node-dev
    restart: unless-stopped
    working_dir: /workspace
    volumes:
      - ./node-workspace:/workspace
    command: tail -f /dev/null
    networks:
      - dev-network

  ubuntu-dev:
    image: ubuntu:22.04
    container_name: ubuntu-dev
    restart: unless-stopped
    working_dir: /workspace
    volumes:
      - ./ubuntu-workspace:/workspace
    command: tail -f /dev/null
    networks:
      - dev-network

networks:
  dev-network:
    external: true
EOF

    # Create workspace directories
    mkdir -p "$DOCKER_COMPOSE_DIR/development/python-workspace"
    mkdir -p "$DOCKER_COMPOSE_DIR/development/node-workspace"
    mkdir -p "$DOCKER_COMPOSE_DIR/development/ubuntu-workspace"
    
    log "[+] Development containers configured"
}

# Create management scripts
create_management_scripts() {
    log "[i] Creating management scripts..."
    
    # Lab control script
    cat > "$DOCKER_COMPOSE_DIR/lab-control.sh" << 'EOF'
#!/bin/bash
# Docker Lab Control Script

COMPOSE_DIR="$(dirname "$0")"
cd "$COMPOSE_DIR"

case "$1" in
    start)
        echo "[+] Starting Docker Lab Environment..."
        docker-compose -f portainer.yml up -d
        docker-compose -f databases/databases.yml up -d
        docker-compose -f web-servers/nginx.yml up -d
        docker-compose -f development/dev-tools.yml up -d
        echo "[+] Lab environment started!"
        echo "[i] Portainer: http://localhost:9000"
        echo "[i] Nginx: http://localhost:80"
        ;;
    stop)
        echo "[!] Stopping Docker Lab Environment..."
        docker-compose -f development/dev-tools.yml down
        docker-compose -f web-servers/nginx.yml down
        docker-compose -f databases/databases.yml down
        docker-compose -f portainer.yml down
        echo "[+] Lab environment stopped!"
        ;;
    restart)
        echo "[i] Restarting Docker Lab Environment..."
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        echo "[i] Docker Lab Status:"
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        ;;
    logs)
        if [ -n "$2" ]; then
            docker logs -f "$2"
        else
            echo "Usage: $0 logs <container-name>"
            echo "Available containers:"
            docker ps --format "{{.Names}}"
        fi
        ;;
    cleanup)
        echo "[i] Cleaning up Docker Lab..."
        docker system prune -f
        docker volume prune -f
        echo "[+] Cleanup completed!"
        ;;
    *)
        echo "Docker Lab Control Script"
        echo "Usage: $0 {start|stop|restart|status|logs|cleanup}"
        echo ""
        echo "Commands:"
        echo "  start   - Start all lab services"
        echo "  stop    - Stop all lab services"
        echo "  restart - Restart all lab services"
        echo "  status  - Show running containers"
        echo "  logs    - Show logs for a container"
        echo "  cleanup - Clean up unused Docker resources"
        ;;
esac
EOF

    chmod +x "$DOCKER_COMPOSE_DIR/lab-control.sh"
    
    # Database connection script
    cat > "$DOCKER_COMPOSE_DIR/db-connect.sh" << 'EOF'
#!/bin/bash
# Database Connection Helper

case "$1" in
    postgres|pg)
        docker exec -it dev-postgres psql -U devuser -d devdb
        ;;
    mysql)
        docker exec -it dev-mysql mysql -u devuser -pdevpass123 devdb
        ;;
    redis)
        docker exec -it dev-redis redis-cli
        ;;
    mongodb|mongo)
        docker exec -it dev-mongodb mongosh -u admin -p adminpass123
        ;;
    *)
        echo "Database Connection Helper"
        echo "Usage: $0 {postgres|mysql|redis|mongodb}"
        ;;
esac
EOF

    chmod +x "$DOCKER_COMPOSE_DIR/db-connect.sh"
    
    log "[+] Management scripts created"
}

# Create useful aliases
create_aliases() {
    log "[i] Creating Docker lab aliases..."
    
    cat > "$HOME/.docker-lab-aliases" << EOF
# Docker Lab Aliases
alias lab-start='$DOCKER_COMPOSE_DIR/lab-control.sh start'
alias lab-stop='$DOCKER_COMPOSE_DIR/lab-control.sh stop'
alias lab-restart='$DOCKER_COMPOSE_DIR/lab-control.sh restart'
alias lab-status='$DOCKER_COMPOSE_DIR/lab-control.sh status'
alias lab-cleanup='$DOCKER_COMPOSE_DIR/lab-control.sh cleanup'
alias lab-logs='$DOCKER_COMPOSE_DIR/lab-control.sh logs'

# Database connections
alias db-postgres='$DOCKER_COMPOSE_DIR/db-connect.sh postgres'
alias db-mysql='$DOCKER_COMPOSE_DIR/db-connect.sh mysql'
alias db-redis='$DOCKER_COMPOSE_DIR/db-connect.sh redis'
alias db-mongo='$DOCKER_COMPOSE_DIR/db-connect.sh mongodb'

# Development containers
alias dev-python='docker exec -it python-dev bash'
alias dev-node='docker exec -it node-dev sh'
alias dev-ubuntu='docker exec -it ubuntu-dev bash'

# Docker shortcuts
alias dps='docker ps'
alias dpsa='docker ps -a'
alias di='docker images'
alias dlog='docker logs -f'
alias dstats='docker stats'
EOF

    # Add to bashrc if not already there
    if ! grep -q "docker-lab-aliases" "$HOME/.bashrc" 2>/dev/null; then
        echo "" >> "$HOME/.bashrc"
        echo "# Docker Lab Aliases" >> "$HOME/.bashrc"
        echo "source ~/.docker-lab-aliases" >> "$HOME/.bashrc"
    fi
    
    log "[+] Aliases created (reload shell or run: source ~/.bashrc)"
}

# Main execution function
main() {
    log "[+] Setting up Docker Lab Environment..."
    
    check_docker
    create_directories
    create_networks
    setup_portainer
    setup_databases
    setup_web_servers
    setup_dev_containers
    create_management_scripts
    create_aliases
    
    log "[+] Docker Lab Environment setup completed!"
    
    info "[i] Quick Start:"
    info "  • Start lab: $DOCKER_COMPOSE_DIR/lab-control.sh start"
    info "  • Or use alias: lab-start (after reloading shell)"
    info ""
    info "[i] Access Points:"
    info "  • Portainer: http://localhost:9000"
    info "  • Nginx: http://localhost:80"
    info ""
    info "[i] Database Connections:"
    info "  • PostgreSQL: localhost:5432 (devuser/devpass123)"
    info "  • MySQL: localhost:3306 (devuser/devpass123)"
    info "  • Redis: localhost:6379"
    info "  • MongoDB: localhost:27017 (admin/adminpass123)"
    info ""
    info "[i] Lab Directory: $DOCKER_COMPOSE_DIR"
    info "[i] Control Script: $DOCKER_COMPOSE_DIR/lab-control.sh"
}

# Run main function
main "$@"
