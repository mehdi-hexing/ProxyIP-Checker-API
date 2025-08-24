import socket
import ssl
import json
import re
import pycountry
import time
import asyncio
import uvicorn
import httpx
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse

HARDCODED_PORT = 12345
CONCURRENCY_LIMIT = 30
semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

IP_RESOLVER = "speed.cloudflare.com"
PATH_RESOLVER = "/meta"
TIMEOUT = 10

async def get_hosting_provider(ip):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://ip-api.com/json/{ip}?fields=as")
            response.raise_for_status()
            data = response.json()
            return data.get("as")
    except (httpx.RequestError, json.JSONDecodeError):
        return None

async def check(host, path, proxy={}):
    ssl_context = ssl.create_default_context()
    start_time = asyncio.get_event_loop().time()
    try:
        ip, port = proxy.get("ip", host), int(proxy.get("port", 443))
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip, port, ssl=ssl_context, server_hostname=host if proxy else None
            ),
            timeout=TIMEOUT
        )
        payload = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   "User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
        writer.write(payload.encode()); await writer.drain()
        resp_bytes = await reader.read()
        end_time = asyncio.get_event_loop().time()
        delay = (end_time - start_time) * 1000
        writer.close(); await writer.wait_closed()
        resp_str = resp_bytes.decode("utf-8", errors="ignore")
        if "\r\n\r\n" not in resp_str: return {"error": "Malformed response"}, 0
        _, body = resp_str.split("\r\n\r\n", 1)
        return json.loads(body), delay
    except Exception as e:
        return {"error": str(e)}, 0

async def process_proxy(ip, port):
    proxy_data = {"ip": ip, "port": port}
    direct_task = check(IP_RESOLVER, PATH_RESOLVER)
    proxy_task = check(IP_RESOLVER, PATH_RESOLVER, proxy=proxy_data)
    
    direct_meta, _ = await direct_task
    proxy_meta, proxy_delay = await proxy_task

    direct_ip = direct_meta.get('clientIp')
    proxy_ip = proxy_meta.get('clientIp')

    is_alive = bool(direct_ip and proxy_ip and direct_ip != proxy_ip)

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
            "message": f"Success: IP changed from {direct_ip} to {proxy_ip}.",
            "ping": f"{round(proxy_delay)}",
            "httpProtocol": proxy_meta.get("httpProtocol", "Unknown"),
            "latitude": proxy_meta.get("latitude", "Unknown"),
            "longitude": proxy_meta.get("longitude", "Unknown")
        }
    else:
        reason = "IP did not change or a connection failed."
        if not direct_ip: reason = f"Direct connection failed: {direct_meta.get('error', 'Unknown')}"
        elif not proxy_ip: reason = f"Proxy connection failed: {proxy_meta.get('error', 'Unknown')}"
        elif direct_ip == proxy_ip: reason = f"IP did not change. Both connections showed IP: {direct_ip}"
        return {"ip": ip, "port": port, "proxyip": False, "message": reason}

app = FastAPI(
    title="Production Proxy Checker API",
    description="Validates a proxy and returns its full details.",
    version="12.0.0"
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
    print(f"Starting PRODUCTION server on http://0.0.0.0:{HARDCODED_PORT}")
    uvicorn.run("checker:app", host="0.0.0.0", port=HARDCODED_PORT, reload=False)
