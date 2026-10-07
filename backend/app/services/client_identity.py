import ipaddress
from app.config import settings


def client_ip(request):
    peer = request.client.host if request.client else "unknown"
    try:
        trusted = [ipaddress.ip_network(cidr) for cidr in settings.TRUSTED_PROXY_CIDRS]
        address = ipaddress.ip_address(peer)
        if not any(address in network for network in trusted): return peer
        forwarded = request.headers.get("x-forwarded-for", "")
        if not forwarded: return peer
        chain = [ipaddress.ip_address(part.strip()) for part in forwarded.split(",")]
        for candidate in reversed(chain):
            if not any(candidate in network for network in trusted): return str(candidate)
        return str(chain[0])
    except ValueError:
        return peer
