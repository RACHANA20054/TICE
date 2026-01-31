from fastapi import FastAPI

app = FastAPI(
    title="AI-Driven Threat Intelligence Correlation Engine",
    description="Consolidated threat intelligence analysis for IP addresses",
    version="1.0"
)

@app.get("/")
def root():
    return {
        "message": "TICE Backend is running successfully 🚀"
    }

@app.get("/analyze/{ip}")
def analyze_ip(ip: str):
    return {
        "ip": ip,
        "status": "Analysis logic will be added here"
    }
