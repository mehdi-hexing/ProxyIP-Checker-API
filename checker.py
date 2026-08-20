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

IP_RESOLVER = "speed.cloudflare.com"
PATH_RESOLVER = "/meta"
TIMEOUT = 10


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
    """Cloudflare's /meta blocks datacenter-originated requests (403), so the
    baseline (no-proxy) IP is fetched from a plain IP-echo service instead."""
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
            except (httpx.RequestError, json.JSONDecodeError, httpx.HTTPStatusError) as e:
                print(f"[DEBUG] get_direct_ip() failed for {url}: {e}")
    return None


async def check(host, path, proxy_ip=None, proxy_port=443):
    """Fetch https://{host}{path}, optionally forcing the TCP connection to
    proxy_ip:proxy_port while keeping SNI/Host as `host` (the 'ProxyIP'
    trick). Uses curl_cffi with a Chrome TLS fingerprint since Cloudflare's
    bot management 403s plain-Python TLS clients regardless of source IP."""
    url = f"https://{host}{path}"
    curl_options = {}
    if proxy_ip:
        curl_options[CurlOpt.RESOLVE] = [f"{host}:{proxy_port}:{proxy_ip}"]

    start = asyncio.get_event_loop().time()
    try:
        async with AsyncSession(curl_options=curl_options) as session:
            resp = await session.get(
                url,
                impersonate="chrome",
                timeout=TIMEOUT,
            )
        delay = (asyncio.get_event_loop().time() - start) * 1000
        print(f"[DEBUG] check(host={host}, proxy_ip={proxy_ip}) status={resp.status_code} body[:300]={resp.text[:300]!r}")
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}"}, 0
        return resp.json(), delay
    except Exception as e:
        print(f"[DEBUG] check(host={host}, proxy_ip={proxy_ip}) EXCEPTION: {type(e).__name__}: {e}")
        return {"error": f"{type(e).__name__}: {e}" if str(e) else type(e).__name__}, 0


async def process_proxy(ip, port):
    direct_ip = await get_direct_ip()
    proxy_meta, proxy_delay = await check(IP_RESOLVER, PATH_RESOLVER, proxy_ip=ip, proxy_port=port)

    proxy_ip_result = proxy_meta.get('clientIp')

    is_alive = bool(direct_ip and proxy_ip_result and direct_ip != proxy_ip_result)

    if is_alive:
        final_org_name = await get_hosting_provider(ip)
        if not final_org_name:
            final_org_name = re.sub(r'[^a-zA-Z0-9\s]', '', proxy_meta.get("asOrganization", ""))

        country_code = proxy_meta.get("country", "Unknown")
        country = pycountry.countries.get(alpha_2=country_code)
        country_name = country.name if country else "Unknown"

        return {
            "ip": ip, "port": port, "proxyip": True,
            "asOrganization": final_org_name, "countryCode": country_code,
            "countryName": country_name,
            "asn": proxy_meta.get("asn", "Unknown"),
            "message": f"Success: IP changed from {direct_ip} to {proxy_ip_result}.",
            "ping": f"{round(proxy_delay)}",
            "httpProtocol": proxy_meta.get("httpProtocol", "Unknown"),
            "latitude": proxy_meta.get("latitude", "Unknown"),
            "longitude": proxy_meta.get("longitude", "Unknown")
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
    version="13.0.0"
)


@app.get("/api/v1/check", tags=["Proxy Checker"])
async def check_proxy_endpoint(
    proxyip: str = Query(..., description="The proxy to check in 'IP' or 'IP:PORT' format.", example="36.95.152.58")
):
    async with semaphore:
        try:
            if ":" in proxyip:
                ip, port_str = proxyip.rsplit(":", 1)
                port_number = int(port_str)
            else:
                ip = proxyip
                port_number = 443
            result_data = await process_proxy(ip, port_number)
            return JSONResponse(content=result_data)
        except ValueError:
            return JSONResponse(status_code=400, content={"proxyip": False, "error": "Invalid port format."})
        except Exception as e:
            return JSONResponse(status_code=500, content={"proxyip": False, "error": f"An unexpected internal server error occurred: {e}"})


if __name__ == "__main__":
    print(f"Starting PRODUCTION server on http://0.0.0.0:{PORT}")
    uvicorn.run("checker:app", host="0.0.0.0", port=PORT, reload=False)
