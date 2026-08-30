"""Gateway operational endpoints. Status/fence modules deliberately exclude Vertex imports."""
from fastapi import FastAPI

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@app.get("/readyz")
def readyz():
    return {"status": "requires-signed-policy"}
