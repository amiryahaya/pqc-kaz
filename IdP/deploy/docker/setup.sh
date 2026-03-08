#!/bin/bash
# =============================================================================
# PQC Identity Platform - Development Environment Setup
# =============================================================================
# Usage: ./setup.sh [command]
# Commands:
#   start       - Start all services (default)
#   stop        - Stop all services
#   restart     - Restart all services
#   status      - Show service status
#   logs        - Show logs (follow mode)
#   clean       - Stop and remove all data
#   infra       - Start only infrastructure (PostgreSQL, Redis, SoftHSM)
#   observability - Start only observability stack
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored message
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if .env file exists
check_env() {
    if [ ! -f ".env" ]; then
        warn ".env file not found, creating from .env.example..."
        cp .env.example .env
        success "Created .env file. Please review and adjust settings if needed."
    fi
}

# Start infrastructure services
start_infra() {
    info "Starting infrastructure services (PostgreSQL, Redis, SoftHSM)..."
    docker-compose up -d
    success "Infrastructure services started!"
}

# Start observability services
start_observability() {
    info "Starting observability services (Jaeger, Prometheus, Grafana, Seq)..."
    docker-compose -f docker-compose.observability.yml up -d
    success "Observability services started!"
}

# Start all services
start_all() {
    check_env
    info "Starting all services..."
    docker-compose -f docker-compose.yml -f docker-compose.observability.yml up -d
    success "All services started!"
    print_urls
}

# Stop all services
stop_all() {
    info "Stopping all services..."
    docker-compose -f docker-compose.yml -f docker-compose.observability.yml down
    success "All services stopped!"
}

# Restart all services
restart_all() {
    stop_all
    start_all
}

# Show service status
show_status() {
    info "Service status:"
    docker-compose -f docker-compose.yml -f docker-compose.observability.yml ps
}

# Show logs
show_logs() {
    local service="${1:-}"
    if [ -n "$service" ]; then
        docker-compose -f docker-compose.yml -f docker-compose.observability.yml logs -f "$service"
    else
        docker-compose -f docker-compose.yml -f docker-compose.observability.yml logs -f
    fi
}

# Clean all data
clean_all() {
    warn "This will remove all containers and data volumes!"
    read -p "Are you sure? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Stopping and removing all containers and volumes..."
        docker-compose -f docker-compose.yml -f docker-compose.observability.yml down -v
        success "All containers and volumes removed!"
    else
        info "Cancelled."
    fi
}

# Wait for service to be healthy
wait_for_service() {
    local service=$1
    local max_attempts=${2:-30}
    local attempt=1
    
    info "Waiting for $service to be healthy..."
    while [ $attempt -le $max_attempts ]; do
        if docker-compose -f docker-compose.yml -f docker-compose.observability.yml ps "$service" | grep -q "healthy"; then
            success "$service is healthy!"
            return 0
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    error "$service failed to become healthy after $max_attempts attempts"
    return 1
}

# Print service URLs
print_urls() {
    echo ""
    echo "=============================================="
    echo "  Development Environment URLs"
    echo "=============================================="
    echo ""
    echo "  Infrastructure:"
    echo "    PostgreSQL:  localhost:5432"
    echo "    Redis:       localhost:6379"
    echo ""
    echo "  Observability:"
    echo "    Jaeger UI:   http://localhost:16686"
    echo "    Prometheus:  http://localhost:9090"
    echo "    Grafana:     http://localhost:3000 (admin/admin)"
    echo "    Seq:         http://localhost:8081"
    echo ""
    echo "  API Endpoints (when running):"
    echo "    API:         http://localhost:5000"
    echo "    Swagger:     http://localhost:5000/swagger"
    echo "    Metrics:     http://localhost:5000/metrics"
    echo "    Health:      http://localhost:5000/health"
    echo ""
    echo "=============================================="
}

# Main command handler
case "${1:-start}" in
    start)
        start_all
        ;;
    stop)
        stop_all
        ;;
    restart)
        restart_all
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$2"
        ;;
    clean)
        clean_all
        ;;
    infra)
        check_env
        start_infra
        ;;
    observability)
        check_env
        start_observability
        ;;
    urls)
        print_urls
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|clean|infra|observability|urls}"
        exit 1
        ;;
esac
