from fastapi import FastAPI
from api import rg_api, mb_api, endpoint_api

app = FastAPI(title="PrivBox DPI System")

# Include routers
app.include_router(rg_api.router, prefix="/rg", tags=["Rule Generator"])
app.include_router(mb_api.router, prefix="/mb", tags=["Middlebox"])
app.include_router(endpoint_api.router, prefix="/endpoint", tags=["Endpoints"])

@app.get("/")
async def root():
    return {"message": "PrivBox DPI System", "status": "initializing"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)