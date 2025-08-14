# checker.py# The final, correct, and clean version. It properly parses the nested JSON from the risk API.

import socket
import ssl
import json
import re
import pycountry
import time
import asyncio
import uvicorn
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse

# --- Settings ---
# !! Replace with your actual assigned port from serv00 !!
HARDCODED_PORT = 33163
CONCURRENCY_LIMIT = 30
semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

# --- Logic ---
IP_RESOLVER = "speed.cloudflare.com"
PATH_RESOLVER = "/meta"
RISK_API_HOST = "ipinfo.mehdizrg88.workers.dev"
TIMEOUT = 10

async def check(host, path, proxy={}):
    """A generic async HTTP check function."""
    ssl_context = ssl.create_default_context()
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
        writer.close(); await writer.wait_closed()
        resp_str = resp_bytes.decode("utf-8", errors="ignore")
        if "\r\n\r\n" not in resp_str: return {"error": "Malformed response"}
        _, body = resp_str.split("\r\n\r\n", 1)
        return json.loads(body)
    except Exception as e:
        return {"error": str(e)}

async def get_risk_info(proxy_data: dict):
    """Fetches risk information by correctly parsing the nested 'security' object."""
    path = "/"
    risk_data = await check(RISK_API_HOST, path, proxy=proxy_data)
    
    if risk_data and not risk_data.get("error"):
        # --- THE FIX IS HERE ---
        # We access the 'security' object first, then get the keys from it.
        # .get('security', {}) is a safe way to prevent errors if 'security' key is missing.
        security_info = risk_data.get('security', {})
        return {
            "riskScore": security_info.get("riskScore", "N/A"),
            "riskLevel": security_info.get("riskLevel", "N/A")
        }
    return {
        "riskScore": "Error",
        "riskLevel": f"Failed to fetch: {risk_data.get('error', 'Unknown')}"
    }

async def process_proxy(ip, port):
    """The main processing logic."""
    proxy_data = {"ip": ip, "port": port}
    direct_task = check(IP_RESOLVER, PATH_RESOLVER)
    proxy_task = check(IP_RESOLVER, PATH_RESOLVER, proxy=proxy_data)
    
    direct_meta = await direct_task
    proxy_meta = await proxy_task

    direct_ip = direct_meta.get('clientIp')
    proxy_ip = proxy_meta.get('clientIp')

    is_alive = bool(direct_ip and proxy_ip and direct_ip != proxy_ip)

    if is_alive:
        risk_info_task = get_risk_info(proxy_data)
        org_name = re.sub(r'[^a-zA-Z0-9\s]', '', proxy_meta.get("asOrganization", ""))
        country_code = proxy_meta.get("country", "Unknown")
        country = pycountry.countries.get(alpha_2=country_code)
        country_name = country.name if country else "Unknown"
        risk_info = await risk_info_task
        
        return {
            "ip": ip, "port": port, "proxyip": True,
            "asOrganization": org_name, "countryCode": country_code,
            "countryName": country_name,
            "asn": proxy_meta.get("asn", "Unknown"),
            "riskScore": risk_info.get("riskScore"),
            "riskLevel": risk_info.get("riskLevel"),
            "message": f"Success: IP changed from {direct_ip} to {proxy_ip}.",
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

# --- FastAPI App & Runner ---
app = FastAPI(
    title="Production Proxy Checker API",
    description="Validates a proxy, uses it to fetch its risk score, and returns full details.",
    version="12.0.0"
)

@app.get("/api/v1/check", tags=["Proxy Checker"])
async def check_proxy_endpoint(
    proxy: str = Query(..., description="The proxy to check in 'IP' or 'IP:PORT' format.", example="36.95.152.58")
):
    async with semaphore:
        try:
            if ":" in proxy:
                ip, port_str = proxy.rsplit(":", 1)
                port_number = int(port_str)
            else:
                ip = proxy
                port_number = 443
            result_data = await process_proxy(ip, port_number)
            return JSONResponse(content=result_data)
        except ValueError:
            return JSONResponse(status_code=400, content={"proxyip": False, "error": "Invalid port format."})
        except Exception as e:
            return JSONResponse(status_code=500, content={"proxyip": False, "error": f"An unexpected internal server error occurred: {e}"})

if __name__ == "__main__":
    # Remember to change the filename here to match what you saved
    print(f"Starting PRODUCTION server on http://0.0.0.0:{HARDCODED_PORT}")
    uvicorn.run("checker:app", host="0.0.0.0", port=HARDCODED_PORT, reload=False)
