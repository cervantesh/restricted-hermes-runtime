"""Fixed local UDS launcher; no TCP bind surface."""
import os
import uvicorn

def main() -> None:
    os.umask(0o007)
    app=os.environ["RESTRICTED_UDS_APP"]; path=os.environ["RESTRICTED_UDS_PATH"]
    if path not in {"/run/restricted-inference/gateway.sock","/run/restricted-inference/conversation.sock"}: raise RuntimeError("closed UDS path required")
    uvicorn.run(app,uds=path)
if __name__=="__main__": main()
