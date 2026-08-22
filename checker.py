import asyncio
import json
import os
import re
import pycountry
import uvicorn
import httpx
from curl_cffi.const import CurlOpt
from curl_cffi.requests import AsyncSession
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

PORT = int(os.environ.get("PORT", 8000))
CONCURRENCY_LIMIT = 30
semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

# /meta is behind Cloudflare's Bot Management (blocks non-browser clients
# outright, even with a matching TLS fingerprint). /cdn-cgi/trace is the
# lightweight, unprotected diagnostic endpoint used by proxy-checker tools.
IP_RESOLVER = "speed.cloudflare.com"
PATH_RESOLVER = "/cdn-cgi/trace"
TIMEOUT = 10


def parse_trace(text):
    """Parse Cloudflare's /cdn-cgi/trace plaintext key=value response."""
    data = {}
    for line in text.strip().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            data[key.strip()] = value.strip()
    return data


def parse_proxyip_input(proxyip: str):
    """Parse a proxyip query param into (host, port).

    Accepts:
      - IPv4:            "1.2.3.4"            -> ("1.2.3.4", 443)
      - IPv4:port:        "1.2.3.4:8443"        -> ("1.2.3.4", 8443)
      - bare IPv6:         "2001:db8::1"         -> ("2001:db8::1", 443)
      - bracketed IPv6:     "[2001:db8::1]"        -> ("2001:db8::1", 443)
      - bracketed IPv6:port: "[2001:db8::1]:8443"    -> ("2001:db8::1", 8443)
      - hostname / hostname:port are also supported.
    A bare (unbracketed) IPv6 address is detected by having 2+ colons,
    since only IPv6 literals legitimately contain more than one.
    """
    proxyip = proxyip.strip()

    if proxyip.startswith('['):
        if ']:' in proxyip:
            ip_part, port_str = proxyip.rsplit(']:', 1)
            return ip_part[1:], int(port_str)
        return proxyip.strip('[]'), 443

    if proxyip.count(':') >= 2:
        # Bare IPv6 literal, no port possible without brackets.
        return proxyip, 443

    if ':' in proxyip:
        ip, port_str = proxyip.rsplit(':', 1)
        return ip, int(port_str)

    return proxyip, 443


async def get_hosting_provider(ip):
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.get(f"http://ip-api.com/json/{ip}?fields=as")
            response.raise_for_status()
            data = response.json()
            return data.get("as")
    except (httpx.RequestError, json.JSONDecodeError):
        return None


async def get_direct_ip():
    """Baseline (no-proxy) public IP, via a plain IP-echo service."""
    urls = [
        "https://api.ipify.org?format=json",
        "https://api64.ipify.org?format=json",
    ]
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for url in urls:
            try:
                response = await client.get(url)
                response.raise_for_status()
                ip = response.json().get("ip")
                if ip:
                    return ip
            except (httpx.RequestError, json.JSONDecodeError, httpx.HTTPStatusError):
                pass
    return None


async def check(host, path, proxy_ip=None, proxy_port=443):
    """Fetch https://{host}{path}, optionally forcing the TCP connection to
    proxy_ip:proxy_port while keeping SNI/Host as `host` (the 'ProxyIP'
    trick), then parse the cdn-cgi/trace key=value response."""
    url = f"https://{host}{path}"
    curl_options = {}
    if proxy_ip:
        # libcurl's CURLOPT_RESOLVE requires IPv6 literals to be bracketed
        # in the ADDRESS field (HOST:PORT:[ADDRESS]), unlike IPv4/hostnames.
        resolve_addr = f"[{proxy_ip}]" if ':' in proxy_ip else proxy_ip
        curl_options[CurlOpt.RESOLVE] = [f"{host}:{proxy_port}:{resolve_addr}"]

    start = asyncio.get_event_loop().time()
    try:
        async with AsyncSession(curl_options=curl_options) as session:
            resp = await session.get(
                url,
                impersonate="chrome",
                timeout=TIMEOUT,
            )
            delay = (asyncio.get_event_loop().time() - start) * 1000

            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}, 0

            parsed = parse_trace(resp.text)
            if not parsed.get("ip"):
                return {"error": "Malformed trace response"}, 0

            return parsed, delay
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}" if str(e) else type(e).__name__}, 0


async def process_proxy(ip, port):
    direct_ip = await get_direct_ip()
    proxy_meta, proxy_delay = await check(IP_RESOLVER, PATH_RESOLVER, proxy_ip=ip, proxy_port=port)

    proxy_ip_result = proxy_meta.get('ip')
    is_alive = bool(direct_ip and proxy_ip_result and direct_ip != proxy_ip_result)

    if is_alive:
        final_org_name = await get_hosting_provider(ip)
        if not final_org_name:
            final_org_name = "Unknown"

        country_code = proxy_meta.get("loc", "Unknown")
        country = pycountry.countries.get(alpha_2=country_code)
        country_name = country.name if country else "Unknown"

        return {
            "ip": ip, "port": port, "proxyip": True,
            "asOrganization": final_org_name, "countryCode": country_code,
            "countryName": country_name,
            "colo": proxy_meta.get("colo", "Unknown"),
            "message": f"Success: IP changed from {direct_ip} to {proxy_ip_result}.",
            "ping": f"{round(proxy_delay)}",
            "httpProtocol": proxy_meta.get("http", "Unknown"),
            "tls": proxy_meta.get("tls", "Unknown"),
        }
    else:
        reason = "IP did not change or a connection failed."
        if not direct_ip:
            reason = "Direct IP lookup failed (could not reach ipify)."
        elif not proxy_ip_result:
            reason = f"Proxy connection failed: {proxy_meta.get('error', 'Unknown')}"
        elif direct_ip == proxy_ip_result:
            reason = f"IP did not change. Both connections showed IP: {direct_ip}"
        return {"ip": ip, "port": port, "proxyip": False, "message": reason}


app = FastAPI(
    title="Production Proxy Checker API",
    description="Validates a proxy and returns its full details.",
    version="14.0.0"
)


@app.get("/api/v1/check", tags=["Proxy Checker"])
async def check_proxy_endpoint(
    proxyip: str = Query(..., description="The proxy to check in 'IP' or 'IP:PORT' format.", example="36.95.152.58")
):
    async with semaphore:
        try:
            ip, port_number = parse_proxyip_input(proxyip)
            result_data = await process_proxy(ip, port_number)
            return JSONResponse(content=result_data)
        except ValueError:
            return JSONResponse(status_code=400, content={"proxyip": False, "error": "Invalid port format."})
        except Exception as e:
            return JSONResponse(status_code=500, content={"proxyip": False, "error": f"An unexpected internal server error occurred: {e}"})


if __name__ == "__main__":
    print(f"Starting PRODUCTION server on http://0.0.0.0:{PORT}")
    uvicorn.run("checker:app", host="0.0.0.0", port=PORT, reload=False)

